package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
)

type userSnapshot struct {
	NextID  uint64                         `json:"next_id"`
	Users   map[uint64]*domain.User        `json:"users"`
	Traffic map[uint64]*domain.TrafficStats `json:"traffic"`
	Plans   []domain.Plan                  `json:"plans"`
}

// FileStore 持久化用户库到 disk (users.json)，保障 VPS 重启/服务更新不丢账号与专属 Slug
type FileStore struct {
	mu      sync.RWMutex
	path    string
	users   map[uint64]*domain.User
	traffic map[uint64]*domain.TrafficStats
	plans   []domain.Plan
	nextID  uint64
}

// NewFileStore 打开或创建用户数据持久化文件
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		path = filepath.Join("data", "users.json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("user data dir: %w", err)
	}

	now := time.Now()
	fs := &FileStore{
		path:    path,
		users:   make(map[uint64]*domain.User),
		traffic: make(map[uint64]*domain.TrafficStats),
		plans: []domain.Plan{
			{ID: 1, Name: "月度套餐", DurationMonths: 1, TrafficBytes: 107374182400, PriceCents: 999, Status: true, CreatedAt: now},
			{ID: 2, Name: "季度套餐", DurationMonths: 3, TrafficBytes: 322122547200, PriceCents: 2499, Status: true, CreatedAt: now},
			{ID: 3, Name: "年度套餐", DurationMonths: 12, TrafficBytes: 1073741824000, PriceCents: 7999, Status: true, CreatedAt: now},
		},
	}

	if err := fs.load(); err != nil {
		return nil, err
	}
	return fs, nil
}

func (f *FileStore) load() error {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snap userSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("parse users json: %w", err)
	}
	if snap.Users != nil {
		f.users = snap.Users
	}
	if snap.Traffic != nil {
		f.traffic = snap.Traffic
	}
	if len(snap.Plans) > 0 {
		f.plans = snap.Plans
	}
	f.nextID = snap.NextID
	return nil
}

func (f *FileStore) persistLocked() error {
	snap := userSnapshot{
		NextID:  f.nextID,
		Users:   f.users,
		Traffic: f.traffic,
		Plans:   f.plans,
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *FileStore) SetStaff(id uint64, staff bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[id]; ok {
		u.IsStaff = staff
		_ = f.persistLocked()
	}
}

func (f *FileStore) CreateUser(u *domain.User) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.users {
		if existing.Username == u.Username {
			return 0, errors.New("username already exists")
		}
	}
	f.nextID++
	u.ID = f.nextID
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now
	f.users[u.ID] = u
	f.traffic[u.ID] = &domain.TrafficStats{UserID: u.ID, LimitBytes: 107374182400, UpdatedAt: now}
	if err := f.persistLocked(); err != nil {
		return 0, err
	}
	return u.ID, nil
}

func (f *FileStore) GetUser(id uint64) (*domain.User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	u, ok := f.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (f *FileStore) GetUserByUsername(username string) (*domain.User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, u := range f.users {
		if u.Username == username {
			cp := *u
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (f *FileStore) GetUserBySlug(slug string) (*domain.User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, u := range f.users {
		if u.SubSlug != "" && u.SubSlug == slug {
			cp := *u
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (f *FileStore) ListUsers(page, pageSize int) ([]domain.User, int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var all []domain.User
	for _, u := range f.users {
		all = append(all, *u)
	}
	start := (page - 1) * pageSize
	if start >= len(all) {
		return nil, len(all), nil
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], len(all), nil
}

func (f *FileStore) UpdateUser(id uint64, email *string, status *bool, isStaff *bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return ErrNotFound
	}
	if email != nil {
		u.Email = *email
	}
	if status != nil {
		u.Status = *status
	}
	if isStaff != nil {
		u.IsStaff = *isStaff
	}
	u.UpdatedAt = time.Now()
	return f.persistLocked()
}

func (f *FileStore) DeleteUser(id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.users, id)
	delete(f.traffic, id)
	return f.persistLocked()
}

func (f *FileStore) GetTraffic(userID uint64) (*domain.TrafficStats, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	s, ok := f.traffic[userID]
	if !ok {
		return &domain.TrafficStats{UserID: userID, LimitBytes: 107374182400}, nil
	}
	cp := *s
	return &cp, nil
}

func (f *FileStore) ListPlans(activeOnly bool) ([]domain.Plan, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !activeOnly {
		return f.plans, nil
	}
	var active []domain.Plan
	for _, p := range f.plans {
		if p.Status {
			active = append(active, p)
		}
	}
	return active, nil
}
