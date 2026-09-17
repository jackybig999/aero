package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/node/domain"
)

var ErrNotFound = fmt.Errorf("node not found")

type Store interface {
	Create(n *domain.Node) (uint64, error)
	Get(id uint64) (*domain.Node, error)
	ListAll() ([]domain.Node, error)
	ListAvailable() ([]domain.Node, error)
	UpdateStatus(id uint64, online bool, version string) error
	Delete(id uint64) error
	// DeleteMatching removes nodes by vps_id and/or IP; returns deleted node IDs.
	DeleteMatching(vpsID uint64, ip string) ([]uint64, error)
}

type MemoryStore struct {
	mu    sync.RWMutex
	nodes map[uint64]*domain.Node
	next  uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{nodes: make(map[uint64]*domain.Node)}
}

func (m *MemoryStore) Create(n *domain.Node) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	n.ID = m.next
	n.CreatedAt = time.Now()
	n.UpdatedAt = time.Now()
	m.nodes[n.ID] = n
	return n.ID, nil
}

func (m *MemoryStore) Get(id uint64) (*domain.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[id]
	if !ok {
		return nil, ErrNotFound
	}
	return n, nil
}

func (m *MemoryStore) ListAll() ([]domain.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]domain.Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		result = append(result, *n)
	}
	return result, nil
}

func (m *MemoryStore) ListAvailable() ([]domain.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []domain.Node
	for _, n := range m.nodes {
		if n.Status && !n.IsBackup {
			result = append(result, *n)
		}
	}
	return result, nil
}

func (m *MemoryStore) UpdateStatus(id uint64, online bool, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return ErrNotFound
	}
	n.Status = online
	if version != "" { n.AgentVersion = version }
	now := time.Now()
	n.LastHeartbeat = &now
	n.UpdatedAt = now
	return nil
}

func (m *MemoryStore) Delete(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id)
	return nil
}

func (m *MemoryStore) DeleteMatching(vpsID uint64, ip string) ([]uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []uint64
	for id, n := range m.nodes {
		match := false
		if vpsID > 0 && n.VPSID == vpsID {
			match = true
		}
		if ip != "" && n.IP == ip {
			match = true
		}
		if match {
			ids = append(ids, id)
			delete(m.nodes, id)
		}
	}
	return ids, nil
}
