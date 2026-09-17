package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/secret"
)

// FileStore persists VPS registry. At rest:
//   - SSH passwords: AES-256-GCM ciphertext (passwords map)
//   - IPs: AES-256-GCM ciphertext (ips map)
// Host JSON never keeps plaintext password; IP field is blanked on disk.
type FileStore struct {
	mu        sync.Mutex
	path      string
	box       *secret.Box
	mem       *MemoryStore
	ipCipher  map[uint64]string // last known IP ciphertext — never wipe on empty memory IP
}

type fileSnapshot struct {
	Next      uint64                     `json:"next"`
	Hosts     map[uint64]*domain.VPSHost `json:"hosts"`
	Passwords map[uint64]string          `json:"passwords"` // AES-GCM password
	IPs       map[uint64]string          `json:"ips"`       // AES-GCM IP
}

// NewFileStore loads existing data from path (or creates empty).
func NewFileStore(path string, box *secret.Box) (*FileStore, error) {
	if path == "" {
		path = filepath.Join("data", "vps.json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	if box == nil {
		return nil, fmt.Errorf("crypto box required for durable VPS store")
	}
	fs := &FileStore{
		path:     path,
		box:      box,
		mem:      NewMemoryStore(),
		ipCipher: map[uint64]string{},
	}
	needMigrate, err := fs.load()
	if err != nil {
		return nil, err
	}
	// Only rewrite disk when we migrated plaintext IP → cipher (avoid wiping ips)
	if needMigrate {
		if err := fs.persist(); err != nil {
			return nil, fmt.Errorf("migrate save: %w", err)
		}
	}
	return fs, nil
}

// load returns needMigrate=true if any host still had plaintext IP on disk.
func (f *FileStore) load() (needMigrate bool, err error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if len(raw) == 0 {
		return false, nil
	}
	var snap fileSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return false, fmt.Errorf("parse %s: %w", f.path, err)
	}
	f.mem.mu.Lock()
	defer f.mem.mu.Unlock()
	if snap.Hosts == nil {
		snap.Hosts = map[uint64]*domain.VPSHost{}
	}
	if snap.Passwords == nil {
		snap.Passwords = map[uint64]string{}
	}
	if snap.IPs == nil {
		snap.IPs = map[uint64]string{}
	}
	for id, cip := range snap.IPs {
		if cip != "" {
			f.ipCipher[id] = cip
		}
	}
	for id, h := range snap.Hosts {
		if h == nil {
			continue
		}
		// Restore IP from cipher first
		if cip, ok := snap.IPs[id]; ok && cip != "" {
			if plain, err := f.box.Decrypt(cip); err == nil && plain != "" {
				h.IP = plain
			}
		}
		// Legacy: plaintext IP in JSON → encrypt on next migrate save
		if h.IP != "" {
			if _, has := snap.IPs[id]; !has || snap.IPs[id] == "" {
				needMigrate = true
			}
			if cip, err := f.box.Encrypt(h.IP); err == nil {
				f.ipCipher[id] = cip
			}
		}
		f.mem.hosts[id] = h
		if p, ok := snap.Passwords[id]; ok {
			f.mem.passwords[id] = p
		}
		if id > f.mem.next {
			f.mem.next = id
		}
	}
	if snap.Next > f.mem.next {
		f.mem.next = snap.Next
	}
	return needMigrate, nil
}

func (f *FileStore) saveLocked() error {
	f.mem.mu.RLock()
	snap := fileSnapshot{
		Next:      f.mem.next,
		Hosts:     make(map[uint64]*domain.VPSHost, len(f.mem.hosts)),
		Passwords: make(map[uint64]string, len(f.mem.passwords)),
		IPs:       make(map[uint64]string, len(f.mem.hosts)),
	}
	for id, h := range f.mem.hosts {
		cp := *h
		if h.Metrics != nil {
			mc := *h.Metrics
			cp.Metrics = &mc
		}
		if h.LastProbeAt != nil {
			t := *h.LastProbeAt
			cp.LastProbeAt = &t
		}
		// Encrypt current IP; if empty, keep last ciphertext (never erase)
		if h.IP != "" && f.box != nil {
			if cip, err := f.box.Encrypt(h.IP); err == nil {
				f.ipCipher[id] = cip
			}
		}
		if cip := f.ipCipher[id]; cip != "" {
			snap.IPs[id] = cip
		}
		cp.IP = "" // strip plaintext from JSON
		snap.Hosts[id] = &cp
		if p, ok := f.mem.passwords[id]; ok {
			snap.Passwords[id] = p
		}
	}
	f.mem.mu.RUnlock()

	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *FileStore) persist() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saveLocked()
}

// SetHostIP updates plaintext IP in memory and persists encrypted.
func (f *FileStore) SetHostIP(id uint64, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip required")
	}
	f.mem.mu.Lock()
	h, ok := f.mem.hosts[id]
	if !ok {
		f.mem.mu.Unlock()
		return ErrNotFound
	}
	h.IP = ip
	h.UpdatedAt = time.Now()
	f.mem.mu.Unlock()
	return f.persist()
}

func (f *FileStore) Create(h *domain.VPSHost, passwordCipher string) (uint64, error) {
	id, err := f.mem.Create(h, passwordCipher)
	if err != nil {
		return 0, err
	}
	if h.IP != "" && f.box != nil {
		if cip, err := f.box.Encrypt(h.IP); err == nil {
			f.mu.Lock()
			f.ipCipher[id] = cip
			f.mu.Unlock()
		}
	}
	if err := f.persist(); err != nil {
		return id, fmt.Errorf("created but save failed: %w", err)
	}
	return id, nil
}

func (f *FileStore) Get(id uint64) (*domain.VPSHost, string, error) {
	return f.mem.Get(id)
}

func (f *FileStore) List() ([]domain.VPSHost, error) {
	return f.mem.List()
}

func (f *FileStore) SetPassword(id uint64, passwordCipher string) error {
	if err := f.mem.SetPassword(id, passwordCipher); err != nil {
		return err
	}
	return f.persist()
}

func (f *FileStore) UpdateStatus(id uint64, status string) error {
	if err := f.mem.UpdateStatus(id, status); err != nil {
		return err
	}
	return f.persist()
}

func (f *FileStore) UpdateMetrics(id uint64, met *domain.HostMetrics, status string) error {
	if err := f.mem.UpdateMetrics(id, met, status); err != nil {
		return err
	}
	return f.persist()
}

func (f *FileStore) Delete(id uint64) error {
	if err := f.mem.Delete(id); err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.ipCipher, id)
	f.mu.Unlock()
	return f.persist()
}

func (f *FileStore) Path() string { return f.path }

var _ Store = (*FileStore)(nil)

// MaskIP returns a partially redacted IP for logs (not used in storage).
func MaskIP(ip string) string {
	ip = strings.TrimSpace(ip)
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + ".***.***." + parts[3]
	}
	if len(ip) > 8 {
		return ip[:4] + "…" + ip[len(ip)-2:]
	}
	return "***"
}
