package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/domain"
)

var ErrNotFound = fmt.Errorf("plan not found")

type Store interface {
	CreatePlan(p *domain.Plan) (int32, error)
	GetPlan(id int32) (*domain.Plan, error)
	ListPlans(activeOnly bool) ([]domain.Plan, error)
	UpdatePlan(id int32, price *int64, status *bool) error
}

type MemoryStore struct {
	mu     sync.RWMutex
	plans  map[int32]*domain.Plan
	nextID int32
}

func NewMemoryStore() *MemoryStore {
	m := &MemoryStore{plans: make(map[int32]*domain.Plan)}
	for i, v := range defaultPlans {
		m.nextID++
		p := v
		p.ID = m.nextID
		p.Status = true
		p.CreatedAt = time.Now()
		m.plans[p.ID] = &p
		_ = i
	}
	return m
}

var defaultPlans = []domain.Plan{
	{Name: "月度套餐", DurationMonths: 1, TrafficBytes: 100 << 30, PriceCents: 999},
	{Name: "季度套餐", DurationMonths: 3, TrafficBytes: 300 << 30, PriceCents: 2499},
	{Name: "年度套餐", DurationMonths: 12, TrafficBytes: 1 << 40, PriceCents: 7999},
}

func (m *MemoryStore) CreatePlan(p *domain.Plan) (int32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	p.ID = m.nextID
	p.CreatedAt = time.Now()
	m.plans[p.ID] = p
	return p.ID, nil
}

func (m *MemoryStore) GetPlan(id int32) (*domain.Plan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.plans[id]
	if !ok {
		return nil, ErrNotFound
	}
	return p, nil
}

func (m *MemoryStore) ListPlans(activeOnly bool) ([]domain.Plan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []domain.Plan
	for _, p := range m.plans {
		if !activeOnly || p.Status {
			result = append(result, *p)
		}
	}
	return result, nil
}

func (m *MemoryStore) UpdatePlan(id int32, price *int64, status *bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.plans[id]
	if !ok {
		return ErrNotFound
	}
	if price != nil { p.PriceCents = *price }
	if status != nil { p.Status = *status }
	return nil
}
