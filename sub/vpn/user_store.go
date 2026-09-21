// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — 用户数据持久化存储与原子写入
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// UserStore defines storage operations for users.
type UserStore interface {
	CreateUser(u *User) (uint64, error)
	GetUser(id uint64) (*User, error)
	GetUserByUsername(username string) (*User, error)
	GetUserBySlug(slug string) (*User, error)
	ListUsers(page, pageSize int) ([]User, int, error)
	UpdateUser(id uint64, params UpdateUserParams) error
	DeleteUser(id uint64) error
	SetStaff(id uint64, isStaff bool) error
	SetPassword(id uint64, hash string) error
	UpdateSubSlug(id uint64, slug string) error
	Renew(id uint64, planName string, months int32, priceCents int64) (*User, error)
}

// FileUserStore persists users into a JSON file atomically.
type FileUserStore struct {
	mu     sync.RWMutex
	path   string
	users  map[uint64]*User
	nextID uint64
}

func NewFileUserStore(path string) (*FileUserStore, error) {
	s := &FileUserStore{
		path:   path,
		users:  make(map[uint64]*User),
		nextID: 1,
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *FileUserStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	// Normalize any empty expire_at string to null for robust parsing
	data = []byte(strings.ReplaceAll(string(data), `"expire_at": ""`, `"expire_at": null`))
	var list []*User
	if err := json.Unmarshal(data, &list); err == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, u := range list {
			s.users[u.ID] = u
			if u.ID >= s.nextID {
				s.nextID = u.ID + 1
			}
		}
		return nil
	}

	var wrapper struct {
		NextID uint64           `json:"next_id"`
		Users  map[string]*User `json:"users"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Users) > 0 {
		s.mu.Lock()
		defer s.mu.Unlock()
		if wrapper.NextID > 0 {
			s.nextID = wrapper.NextID
		}
		for _, u := range wrapper.Users {
			s.users[u.ID] = u
			if u.ID >= s.nextID {
				s.nextID = u.ID + 1
			}
		}
		return nil
	}
	return errors.New("unrecognized users format")
}

func (s *FileUserStore) save() error {
	if s.path == "" {
		return nil
	}
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileUserStore) CreateUser(u *User) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, exist := range s.users {
		if strings.EqualFold(exist.Username, u.Username) {
			return 0, fmt.Errorf("username %q already exists", u.Username)
		}
		if u.SubSlug != "" && exist.SubSlug == u.SubSlug {
			return 0, fmt.Errorf("slug %q already exists", u.SubSlug)
		}
	}
	u.ID = s.nextID
	s.nextID++
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now
	s.users[u.ID] = u
	return u.ID, s.save()
}

func (s *FileUserStore) GetUser(id uint64) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	cp := *u
	return &cp, nil
}

func (s *FileUserStore) GetUserByUsername(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Username, username) {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *FileUserStore) GetUserBySlug(slug string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.SubSlug == slug {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *FileUserStore) ListUsers(page, pageSize int) ([]User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.users)
	if pageSize <= 0 {
		pageSize = 50
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * pageSize
	if start >= total {
		return []User{}, total, nil
	}
	var all []User
	for _, u := range s.users {
		all = append(all, *u)
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return all[start:end], total, nil
}

func (s *FileUserStore) UpdateUser(id uint64, p UpdateUserParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return errors.New("user not found")
	}
	if p.Phone != nil {
		u.Phone = *p.Phone
	}
	if p.Email != nil {
		u.Email = *p.Email
	}
	if p.Status != nil {
		u.Status = *p.Status
	}
	if p.IsStaff != nil {
		u.IsStaff = *p.IsStaff
	}
	if p.PlanName != nil {
		u.PlanName = *p.PlanName
	}
	if p.PlanMonths != nil {
		u.PlanMonths = *p.PlanMonths
	}
	if p.PriceCents != nil {
		u.PriceCents = *p.PriceCents
	}
	u.UpdatedAt = time.Now()
	return s.save()
}

func (s *FileUserStore) DeleteUser(id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
	return s.save()
}

func (s *FileUserStore) SetStaff(id uint64, isStaff bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		u.IsStaff = isStaff
		u.UpdatedAt = time.Now()
		return s.save()
	}
	return errors.New("user not found")
}

func (s *FileUserStore) SetPassword(id uint64, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		u.PasswordHash = hash
		u.UpdatedAt = time.Now()
		return s.save()
	}
	return errors.New("user not found")
}

func (s *FileUserStore) UpdateSubSlug(id uint64, slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		u.SubSlug = slug
		if slug == "superadmin" {
			u.SubToken = "usr_superadmin"
		}
		u.UpdatedAt = time.Now()
		return s.save()
	}
	return errors.New("user not found")
}

func (s *FileUserStore) Renew(id uint64, planName string, months int32, priceCents int64) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	base := time.Now()
	if u.ExpireAt.After(base) {
		base = u.ExpireAt
	}
	u.ExpireAt = base.AddDate(0, int(months), 0)
	u.PlanName = planName
	u.PlanMonths = months
	u.PriceCents = priceCents
	u.UpdatedAt = time.Now()
	_ = s.save()
	cp := *u
	return &cp, nil
}

// MemoryUserStore implements UserStore in memory for tests or fallbacks.
type MemoryUserStore struct {
	*FileUserStore
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		FileUserStore: &FileUserStore{
			users:  make(map[uint64]*User),
			nextID: 1,
		},
	}
}
