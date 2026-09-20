// Copyright 2026 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — VPS 存储接口与内存测试桩
package main

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// VPSStore defines durable storage for VPS machine assets.
type VPSStore interface {
	Get(id uint64) (*VPSHost, error)
	List() ([]*VPSHost, error)
	Create(p CreateVPSParams) (*VPSHost, error)
	Update(id uint64, p UpdateVPSParams) (*VPSHost, error)
	Delete(id uint64) error
	UpdateMetrics(id uint64, m *HostMetrics, probeOK bool, errMsg string, latency int64) error
	UpdatePurity(id uint64, res *PurityResult) error
	UpdateDomain(id uint64, domain string) error
	GetCredentials(id uint64) (*Credentials, error)
}

// MemoryVPSStore in-memory implementation for testing or fallback.
type MemoryVPSStore struct {
	mu        sync.RWMutex
	next      uint64
	hosts     map[uint64]*VPSHost
	passwords map[uint64]string
}

func NewMemoryVPSStore() *MemoryVPSStore {
	return &MemoryVPSStore{
		hosts:     make(map[uint64]*VPSHost),
		passwords: make(map[uint64]string),
	}
}

func (m *MemoryVPSStore) Get(id uint64) (*VPSHost, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *h
	return &cp, nil
}

func (m *MemoryVPSStore) List() ([]*VPSHost, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*VPSHost, 0, len(m.hosts))
	for _, h := range m.hosts {
		cp := *h
		out = append(out, &cp)
	}
	return out, nil
}

func (m *MemoryVPSStore) Create(p CreateVPSParams) (*VPSHost, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	id := m.next
	now := time.Now()
	h := &VPSHost{
		ID:          id,
		Name:        p.Name,
		Role:        p.Role,
		IP:          p.IP,
		SSHPort:     p.SSHPort,
		SSHUsername: p.SSHUsername,
		HasPassword: p.SSHPassword != "",
		Domain:      p.Domain,
		Remark:      p.Remark,
		Status:      "registered",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	m.hosts[id] = h
	if p.SSHPassword != "" {
		m.passwords[id] = p.SSHPassword
	}
	cp := *h
	return &cp, nil
}

func (m *MemoryVPSStore) Update(id uint64, p UpdateVPSParams) (*VPSHost, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	if p.Name != "" {
		h.Name = p.Name
	}
	if p.Role != "" {
		h.Role = p.Role
	}
	if p.SSHPort > 0 {
		h.SSHPort = p.SSHPort
	}
	if p.SSHUsername != "" {
		h.SSHUsername = p.SSHUsername
	}
	if p.Remark != "" {
		h.Remark = p.Remark
	}
	h.UpdatedAt = time.Now()
	cp := *h
	return &cp, nil
}

func (m *MemoryVPSStore) Delete(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.hosts, id)
	delete(m.passwords, id)
	return nil
}

func (m *MemoryVPSStore) UpdateMetrics(id uint64, met *HostMetrics, ok bool, errMsg string, lat int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, found := m.hosts[id]
	if !found {
		return errors.New("not found")
	}
	now := time.Now()
	h.LastProbeAt = &now
	h.UpdatedAt = now
	if ok && met != nil {
		h.Metrics = met
		h.Status = "online"
	} else {
		h.Status = "error"
		if h.Metrics != nil {
			h.Metrics.ProbeOK = false
			h.Metrics.ProbeError = errMsg
		}
	}
	return nil
}

func (m *MemoryVPSStore) UpdatePurity(id uint64, res *PurityResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, found := m.hosts[id]
	if !found {
		return errors.New("not found")
	}
	now := time.Now()
	h.LastPurityProbeAt = &now
	h.UpdatedAt = now
	if res != nil {
		h.PurityScore = res.PurityScore
		h.AIBlocked = res.AIBlocked
		h.GoogleClean = res.GoogleClean
		h.CFClean = res.CFClean
		h.IsWARPEgress = res.IsWARPEgress
	}
	return nil
}

func (m *MemoryVPSStore) UpdateDomain(id uint64, domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, found := m.hosts[id]
	if !found {
		return errors.New("not found")
	}
	h.Domain = strings.TrimSpace(domain)
	h.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryVPSStore) GetCredentials(id uint64) (*Credentials, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return &Credentials{
		VPSID:       h.ID,
		Name:        h.Name,
		IP:          h.IP,
		SSHPort:     h.SSHPort,
		SSHUsername: h.SSHUsername,
		SSHPassword: m.passwords[id],
		Domain:      h.Domain,
	}, nil
}
