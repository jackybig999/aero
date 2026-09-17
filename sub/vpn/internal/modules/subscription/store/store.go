package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/domain"
)

var ErrNotFound = fmt.Errorf("subscription not found")

type Store interface {
	Create(sub *domain.Subscription) (uint64, error)
	GetByUUID(uuid string) (*domain.Subscription, error)
	ListAll() ([]domain.Subscription, error)
	Delete(id uint64) error
	// DeactivateByNodeID marks all subs on node invalid (node removed with VPS).
	DeactivateByNodeID(nodeID uint64) (int, error)
	// DeleteByNodeID hard-deletes subs bound to node.
	DeleteByNodeID(nodeID uint64) (int, error)
}

type MemoryStore struct {
	mu   sync.RWMutex
	subs map[uint64]*domain.Subscription
	next uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{subs: make(map[uint64]*domain.Subscription)}
}

func (m *MemoryStore) Create(sub *domain.Subscription) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	sub.ID = m.next
	sub.CreatedAt = time.Now()
	m.subs[sub.ID] = sub
	return sub.ID, nil
}

func (m *MemoryStore) GetByUUID(uuid string) (*domain.Subscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.subs {
		if s.ClientUUID == uuid && s.Status {
			return s, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) ListAll() ([]domain.Subscription, error) {
	m.mu.RLock(); defer m.mu.RUnlock()
	var result []domain.Subscription
	for _, s := range m.subs { result = append(result, *s) }
	return result, nil
}

func (m *MemoryStore) Delete(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subs, id)
	return nil
}

func (m *MemoryStore) DeactivateByNodeID(nodeID uint64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.subs {
		if s.NodeID == nodeID && s.Status {
			s.Status = false
			n++
		}
	}
	return n, nil
}

func (m *MemoryStore) DeleteByNodeID(nodeID uint64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.subs {
		if s.NodeID == nodeID {
			delete(m.subs, id)
			n++
		}
	}
	return n, nil
}
