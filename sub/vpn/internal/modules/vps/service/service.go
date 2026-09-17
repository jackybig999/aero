package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/secret"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/sshprobe"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

// Service is VPS asset management only — no AERO install.
type Service struct {
	store store.Store
	box   *secret.Box
}

func New(s store.Store, box *secret.Box) *Service {
	return &Service{store: s, box: box}
}

func (s *Service) Create(p domain.CreateVPSParams) (*domain.VPSHost, error) {
	p.IP = strings.TrimSpace(p.IP)
	p.Name = strings.TrimSpace(p.Name)
	p.SSHPassword = strings.TrimSpace(p.SSHPassword)
	p.SSHUsername = strings.TrimSpace(p.SSHUsername)
	p.Domain = strings.TrimSpace(p.Domain)
	if p.Name == "" || p.IP == "" {
		return nil, fmt.Errorf("name and ip required")
	}
	if p.SSHPort <= 0 {
		p.SSHPort = 22
	}
	if p.SSHUsername == "" {
		p.SSHUsername = "root"
	}
	if p.Role == "" {
		p.Role = "node"
	}
	if p.SSHPassword == "" {
		return nil, fmt.Errorf("ssh_password required")
	}
	// AES-GCM ciphertext at rest — never store plaintext password
	cipher, err := s.box.Encrypt(p.SSHPassword)
	if err != nil {
		return nil, fmt.Errorf("encrypt password: %w", err)
	}
	h := &domain.VPSHost{
		Name: p.Name, Role: p.Role, IP: p.IP,
		SSHPort: p.SSHPort, SSHUsername: p.SSHUsername,
		Domain: p.Domain, Remark: p.Remark, Status: "registered",
	}
	if _, err := s.store.Create(h, cipher); err != nil {
		return nil, err
	}
	// wipe plain from stack-ish; response host has no password field
	p.SSHPassword = ""
	return h, nil
}

func (s *Service) List() ([]domain.VPSHost, error) { return s.store.List() }

func (s *Service) Get(id uint64) (*domain.VPSHost, error) {
	h, _, err := s.store.Get(id)
	return h, err
}

func (s *Service) Delete(id uint64) error {
	// VPS module only deletes registry — does NOT touch AERO on the host.
	return s.store.Delete(id)
}

func (s *Service) UpdatePassword(id uint64, plain string) error {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return fmt.Errorf("password required")
	}
	cipher, err := s.box.Encrypt(plain)
	if err != nil {
		return err
	}
	return s.store.SetPassword(id, cipher)
}

// RepairIP restores missing IP into durable store (encrypted).
func (s *Service) RepairIP(id uint64, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip required")
	}
	// Optional interface: FileStore has SetHostIP
	type ipSetter interface {
		SetHostIP(id uint64, ip string) error
	}
	if fs, ok := s.store.(ipSetter); ok {
		return fs.SetHostIP(id, ip)
	}
	// fallback: recreate not available — error
	return fmt.Errorf("store does not support IP repair")
}

// Credentials decrypts password for AERO package jobs (via ProviderAdapter).
func (s *Service) Credentials(id uint64) (*domain.Credentials, error) {
	h, blob, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	pass, err := s.box.Decrypt(blob)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return &domain.Credentials{
		VPSID: h.ID, Name: h.Name, IP: h.IP, SSHPort: h.SSHPort,
		SSHUsername: h.SSHUsername, SSHPassword: pass, Domain: h.Domain,
	}, nil
}

func (s *Service) Probe(id uint64) (*domain.HostMetrics, error) {
	h, blob, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	pass, err := s.box.Decrypt(blob)
	if err != nil {
		m := &domain.HostMetrics{ProbeOK: false, ProbeError: "decrypt failed", Source: "none", CollectedAt: time.Now()}
		_ = s.store.UpdateMetrics(id, m, "offline")
		return m, err
	}
	if pass == "" {
		m := &domain.HostMetrics{ProbeOK: false, ProbeError: "no password", Source: "none", CollectedAt: time.Now()}
		_ = s.store.UpdateMetrics(id, m, "offline")
		return m, fmt.Errorf("no password")
	}
	start := time.Now()
	client, err := sshprobe.Dial(sshprobe.Credentials{
		Host: h.IP, Port: h.SSHPort, User: h.SSHUsername, Password: pass,
	}, 12*time.Second)
	if err != nil {
		m := &domain.HostMetrics{
			ProbeOK: false, ProbeError: err.Error(), Source: "ssh",
			CollectedAt: time.Now(), LatencyMS: time.Since(start).Milliseconds(),
		}
		_ = s.store.UpdateMetrics(id, m, "offline")
		return m, err
	}
	defer client.Close()
	met, err := sshprobe.CollectMetrics(client)
	if err != nil {
		m := &domain.HostMetrics{
			ProbeOK: false, ProbeError: err.Error(), Source: "ssh",
			CollectedAt: time.Now(), LatencyMS: time.Since(start).Milliseconds(),
		}
		_ = s.store.UpdateMetrics(id, m, "error")
		return m, err
	}
	if rx, tx, nerr := sshprobe.CollectNetDelta(client); nerr == nil {
		met.NetRxMbps, met.NetTxMbps = rx, tx
	}
	met.LatencyMS = time.Since(start).Milliseconds()
	met.ProbeOK = true
	_ = s.store.UpdateMetrics(id, met, "online")
	return met, nil
}
