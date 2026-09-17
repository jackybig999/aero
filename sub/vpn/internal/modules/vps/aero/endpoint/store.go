package endpoint

import (
	"sync"
	"time"
)

// Info is edge connection metadata for one VPS (or standalone host).
type Info struct {
	VPSID      uint64    `json:"vps_id"`
	Name       string    `json:"name,omitempty"`
	Host       string    `json:"host"` // public host for sub URL
	IP         string    `json:"ip,omitempty"`
	SubSecret  string    `json:"sub_secret,omitempty"`
	AdminKey   string    `json:"-"` // never JSON to frontend
	HasAdmin   bool      `json:"has_admin"`
	SubURL     string    `json:"sub_url"`
	Version    string    `json:"version,omitempty"`
	Installed  bool      `json:"installed"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Public strips secrets for UI.
func (i Info) Public() map[string]any {
	return map[string]any{
		"vps_id":     i.VPSID,
		"name":       i.Name,
		"host":       i.Host,
		"ip":         i.IP,
		"sub_url":    i.SubURL,
		"has_admin":  i.HasAdmin || i.AdminKey != "",
		"version":    i.Version,
		"installed":  i.Installed,
		"updated_at": i.UpdatedAt,
	}
}

type Store struct {
	mu   sync.RWMutex
	byID map[uint64]*Info
}

func NewStore() *Store {
	return &Store{byID: map[uint64]*Info{}}
}

func (s *Store) Upsert(info Info) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info.UpdatedAt = time.Now()
	if info.SubURL == "" && info.Host != "" && info.SubSecret != "" {
		scheme := "https"
		info.SubURL = scheme + "://" + info.Host + "/sub/" + info.SubSecret
	}
	cp := info
	s.byID[info.VPSID] = &cp
}

func (s *Store) Get(vpsID uint64) (*Info, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.byID[vpsID]
	if !ok {
		return nil, false
	}
	cp := *i
	return &cp, true
}

func (s *Store) Delete(vpsID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, vpsID)
}

func (s *Store) List() []Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Info, 0, len(s.byID))
	for _, i := range s.byID {
		out = append(out, *i)
	}
	return out
}
