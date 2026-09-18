package store

import (
	"errors"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	CreateUser(u *domain.User) (uint64, error)
	GetUser(id uint64) (*domain.User, error)
	GetUserByUsername(username string) (*domain.User, error)
	GetUserBySlug(slug string) (*domain.User, error)
	ListUsers(page, pageSize int) ([]domain.User, int, error)
	UpdateUser(id uint64, email *string, status *bool, isStaff *bool) error
	DeleteUser(id uint64) error
	GetTraffic(userID uint64) (*domain.TrafficStats, error)
	ListPlans(activeOnly bool) ([]domain.Plan, error)
	SetStaff(id uint64, staff bool)
}

type MemoryStore struct {
	mu      sync.RWMutex
	users   map[uint64]*domain.User
	traffic map[uint64]*domain.TrafficStats
	plans   []domain.Plan
	nextID  uint64
}

func NewMemoryStore() *MemoryStore {
	now := time.Now()
	m := &MemoryStore{
		users:   make(map[uint64]*domain.User),
		traffic: make(map[uint64]*domain.TrafficStats),
		plans: []domain.Plan{
			{ID: 1, Name: "月度套餐", DurationMonths: 1, TrafficBytes: 107374182400, PriceCents: 999, Status: true, CreatedAt: now},
			{ID: 2, Name: "季度套餐", DurationMonths: 3, TrafficBytes: 322122547200, PriceCents: 2499, Status: true, CreatedAt: now},
			{ID: 3, Name: "年度套餐", DurationMonths: 12, TrafficBytes: 1073741824000, PriceCents: 7999, Status: true, CreatedAt: now},
		},
	}
	return m
}

func (m *MemoryStore) SetStaff(id uint64, staff bool) {
	m.mu.Lock(); defer m.mu.Unlock()
	if u, ok := m.users[id]; ok { u.IsStaff = staff }
}

func (m *MemoryStore) CreateUser(u *domain.User) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if existing.Username == u.Username {
			return 0, errors.New("username already exists")
		}
	}
	m.nextID++
	u.ID = m.nextID
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	m.users[u.ID] = u
	m.traffic[u.ID] = &domain.TrafficStats{UserID: u.ID, LimitBytes: 107374182400}
	return u.ID, nil
}

func (m *MemoryStore) GetUser(id uint64) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok { return nil, ErrNotFound }
	return u, nil
}

func (m *MemoryStore) GetUserByUsername(username string) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.Username == username { return u, nil }
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) GetUserBySlug(slug string) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.SubSlug != "" && u.SubSlug == slug {
			return u, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) ListUsers(page, pageSize int) ([]domain.User, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []domain.User
	for _, u := range m.users { all = append(all, *u) }
	start := (page - 1) * pageSize
	if start >= len(all) { return nil, len(all), nil }
	end := start + pageSize
	if end > len(all) { end = len(all) }
	return all[start:end], len(all), nil
}

func (m *MemoryStore) UpdateUser(id uint64, email *string, status *bool, isStaff *bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok { return ErrNotFound }
	if email != nil { u.Email = *email }
	if status != nil { u.Status = *status }
	if isStaff != nil { u.IsStaff = *isStaff }
	u.UpdatedAt = time.Now()
	return nil
}
func (m *MemoryStore) DeleteUser(id uint64) error {
	m.mu.Lock(); defer m.mu.Unlock()
	delete(m.users, id); delete(m.traffic, id)
	return nil
}
func (m *MemoryStore) GetTraffic(userID uint64) (*domain.TrafficStats, error) {
	m.mu.RLock(); defer m.mu.RUnlock()
	s, ok := m.traffic[userID]
	if !ok { return &domain.TrafficStats{UserID: userID, LimitBytes: 107374182400}, nil }
	return s, nil
}
func (m *MemoryStore) ListPlans(activeOnly bool) ([]domain.Plan, error) {
	m.mu.RLock(); defer m.mu.RUnlock()
	if !activeOnly { return m.plans, nil }
	var active []domain.Plan
	for _, p := range m.plans {
		if p.Status { active = append(active, p) }
	}
	return active, nil
}
