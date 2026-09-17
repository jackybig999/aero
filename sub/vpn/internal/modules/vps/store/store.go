package store

import (
	"errors"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	Create(h *domain.VPSHost, passwordCipher string) (uint64, error)
	Get(id uint64) (*domain.VPSHost, string, error)
	List() ([]domain.VPSHost, error)
	SetPassword(id uint64, passwordCipher string) error
	UpdateStatus(id uint64, status string) error
	UpdateMetrics(id uint64, m *domain.HostMetrics, status string) error
	Delete(id uint64) error
}

type MemoryStore struct {
	mu        sync.RWMutex
	hosts     map[uint64]*domain.VPSHost
	passwords map[uint64]string
	next      uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		hosts:     make(map[uint64]*domain.VPSHost),
		passwords: make(map[uint64]string),
	}
}

func (m *MemoryStore) Create(h *domain.VPSHost, passwordCipher string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.hosts {
		if e.IP == h.IP && e.SSHPort == h.SSHPort {
			return 0, errors.New("same IP:port already registered")
		}
	}
	m.next++
	h.ID = m.next
	now := time.Now()
	h.CreatedAt, h.UpdatedAt = now, now
	if h.Status == "" {
		h.Status = "registered"
	}
	h.HasPassword = passwordCipher != ""
	m.hosts[h.ID] = h
	m.passwords[h.ID] = passwordCipher
	return h.ID, nil
}

func (m *MemoryStore) Get(id uint64) (*domain.VPSHost, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, "", ErrNotFound
	}
	cp := *h
	if h.Metrics != nil {
		mc := *h.Metrics
		cp.Metrics = &mc
	}
	return &cp, m.passwords[id], nil
}

func (m *MemoryStore) List() ([]domain.VPSHost, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.VPSHost, 0, len(m.hosts))
	for _, h := range m.hosts {
		cp := *h
		if h.Metrics != nil {
			mc := *h.Metrics
			cp.Metrics = &mc
		}
		out = append(out, cp)
	}
	return out, nil
}

func (m *MemoryStore) SetPassword(id uint64, passwordCipher string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return ErrNotFound
	}
	m.passwords[id] = passwordCipher
	h.HasPassword = passwordCipher != ""
	h.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) UpdateStatus(id uint64, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return ErrNotFound
	}
	if status != "" {
		h.Status = status
	}
	h.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) UpdateMetrics(id uint64, met *domain.HostMetrics, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return ErrNotFound
	}
	if met != nil {
		mc := *met
		h.Metrics = &mc
		now := time.Now()
		h.LastProbeAt = &now
	}
	if status != "" {
		h.Status = status
	}
	h.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) Delete(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.hosts, id)
	delete(m.passwords, id)
	return nil
}
