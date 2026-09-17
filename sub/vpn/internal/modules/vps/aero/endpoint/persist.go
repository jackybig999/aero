package endpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Backend is the storage surface used by aero.Service.
type Backend interface {
	Upsert(info Info)
	Get(vpsID uint64) (*Info, bool)
	Delete(vpsID uint64)
	List() []Info
}

// Persist wraps Store with JSON file durability (includes admin_key / sub_secret, mode 0600).
type Persist struct {
	mu    sync.Mutex
	path  string
	inner *Store
}

type fileDTO struct {
	Items []infoDTO `json:"items"`
}

type infoDTO struct {
	VPSID     uint64    `json:"vps_id"`
	Name      string    `json:"name,omitempty"`
	Host      string    `json:"host"`
	IP        string    `json:"ip,omitempty"`
	Port      int       `json:"port,omitempty"`
	SubSecret string    `json:"sub_secret,omitempty"`
	AdminKey  string    `json:"admin_key,omitempty"`
	HasAdmin  bool      `json:"has_admin"`
	SubURL    string    `json:"sub_url"`
	Version   string    `json:"version,omitempty"`
	Installed bool      `json:"installed"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toDTO(i Info) infoDTO {
	port := i.Port
	if port <= 0 {
		port = 443
	}
	return infoDTO{
		VPSID: i.VPSID, Name: i.Name, Host: i.Host, IP: i.IP, Port: port,
		SubSecret: i.SubSecret, AdminKey: i.AdminKey, HasAdmin: i.HasAdmin || i.AdminKey != "",
		SubURL: i.SubURL, Version: i.Version, Installed: i.Installed, UpdatedAt: i.UpdatedAt,
	}
}

func fromDTO(d infoDTO) Info {
	port := d.Port
	if port <= 0 {
		port = 443
	}
	return Info{
		VPSID: d.VPSID, Name: d.Name, Host: d.Host, IP: d.IP, Port: port,
		SubSecret: d.SubSecret, AdminKey: d.AdminKey, HasAdmin: d.HasAdmin || d.AdminKey != "",
		SubURL: d.SubURL, Version: d.Version, Installed: d.Installed, UpdatedAt: d.UpdatedAt,
	}
}

// NewPersist creates a store that loads/saves path (e.g. data/aero_endpoints.json).
func NewPersist(path string) (*Persist, error) {
	if path == "" {
		path = filepath.Join("data", "aero_endpoints.json")
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	p := &Persist{path: path, inner: NewStore()}
	_ = p.load()
	return p, nil
}

func (p *Persist) load() error {
	raw, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var s fileDTO
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	for _, it := range s.Items {
		p.inner.Upsert(fromDTO(it))
	}
	return nil
}

func (p *Persist) save() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.inner.List()
	items := make([]infoDTO, 0, len(list))
	for _, it := range list {
		if full, ok := p.inner.Get(it.VPSID); ok {
			items = append(items, toDTO(*full))
		} else {
			items = append(items, toDTO(it))
		}
	}
	b, err := json.MarshalIndent(fileDTO{Items: items}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

func (p *Persist) Upsert(info Info) {
	p.inner.Upsert(info)
	_ = p.save()
}

func (p *Persist) Get(vpsID uint64) (*Info, bool) {
	return p.inner.Get(vpsID)
}

func (p *Persist) Delete(vpsID uint64) {
	p.inner.Delete(vpsID)
	_ = p.save()
}

func (p *Persist) List() []Info {
	return p.inner.List()
}

func (p *Persist) Path() string { return p.path }

var _ Backend = (*Persist)(nil)
var _ Backend = (*Store)(nil)
