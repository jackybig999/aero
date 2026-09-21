// Copyright 2026 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — VPS 生产级文件持久化存储与 AES-GCM 加密落盘
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

type FileVPSStore struct {
	mu        sync.RWMutex
	path      string
	box       *SecretBox
	next      uint64
	hosts     map[uint64]*VPSHost
	passwords map[uint64]string
}

type vpsPersistFormat struct {
	Next      uint64              `json:"next"`
	NextID    uint64              `json:"next_id"`
	Hosts     map[uint64]*VPSHost `json:"hosts"`
	Passwords map[uint64]string   `json:"passwords"`
	IPs       map[uint64]string   `json:"ips"`
}

func NewFileVPSStore(path string, box *SecretBox) (*FileVPSStore, error) {
	s := &FileVPSStore{
		path:      path,
		box:       box,
		hosts:     make(map[uint64]*VPSHost),
		passwords: make(map[uint64]string),
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *FileVPSStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var doc vpsPersistFormat
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("corrupt vps store: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if doc.Next > 0 {
		s.next = doc.Next
	} else {
		s.next = doc.NextID
	}
	if doc.Hosts != nil {
		s.hosts = doc.Hosts
	}
	if doc.Passwords != nil {
		s.passwords = doc.Passwords
	}
	if doc.IPs != nil && s.box != nil {
		for id, encIP := range doc.IPs {
			if plain, err := s.box.Decrypt(encIP); err == nil {
				if h, ok := s.hosts[id]; ok {
					h.IP = plain
				}
			}
		}
	}
	return nil
}

func (s *FileVPSStore) save() error {
	if s.path == "" {
		return nil
	}
	encIPs := make(map[uint64]string)
	if s.box != nil {
		for id, h := range s.hosts {
			if h.IP != "" {
				if enc, err := s.box.Encrypt(h.IP); err == nil {
					encIPs[id] = enc
				}
			}
		}
	}
	doc := vpsPersistFormat{
		Next:      s.next,
		NextID:    s.next,
		Hosts:     s.hosts,
		Passwords: s.passwords,
		IPs:       encIPs,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
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

func (s *FileVPSStore) Get(id uint64) (*VPSHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *h
	return &cp, nil
}

func (s *FileVPSStore) List() ([]*VPSHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*VPSHost, 0, len(s.hosts))
	for _, h := range s.hosts {
		cp := *h
		out = append(out, &cp)
	}
	return out, nil
}

func (s *FileVPSStore) Create(p CreateVPSParams) (*VPSHost, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := s.next
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
	s.hosts[id] = h
	if p.SSHPassword != "" && s.box != nil {
		if enc, err := s.box.Encrypt(p.SSHPassword); err == nil {
			s.passwords[id] = enc
		}
	}
	_ = s.save()
	cp := *h
	return &cp, nil
}

func (s *FileVPSStore) Update(id uint64, p UpdateVPSParams) (*VPSHost, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[id]
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
	_ = s.save()
	cp := *h
	return &cp, nil
}

func (s *FileVPSStore) Delete(id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.hosts, id)
	delete(s.passwords, id)
	return s.save()
}

func (s *FileVPSStore) UpdateMetrics(id uint64, met *HostMetrics, ok bool, errMsg string, lat int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.hosts[id]
	if !found {
		return errors.New("not found")
	}
	now := time.Now()
	h.LastProbeAt = &now
	h.UpdatedAt = now
	if ok && met != nil {
		h.Metrics = met
		h.Status = "online"
		score, tier, state := CalculateCapacity(met)
		h.HealthScore = score
		h.Tier = tier
		h.CapacityState = state
	} else {
		h.Status = "error"
		h.HealthScore = 0
		h.CapacityState = "offline"
		if h.Metrics != nil {
			h.Metrics.ProbeOK = false
			h.Metrics.ProbeError = errMsg
		}
	}
	return s.save()
}

func (s *FileVPSStore) UpdatePurity(id uint64, res *PurityResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.hosts[id]
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
	return s.save()
}

func (s *FileVPSStore) UpdateDomain(id uint64, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.hosts[id]
	if !found {
		return errors.New("not found")
	}
	h.Domain = strings.TrimSpace(domain)
	h.UpdatedAt = time.Now()
	return s.save()
}

func (s *FileVPSStore) UpdateDNSStatus(id uint64, st *DNSStatusInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.hosts[id]
	if !found {
		return errors.New("not found")
	}
	h.DNSStatus = st
	h.UpdatedAt = time.Now()
	return s.save()
}

func (s *FileVPSStore) UpdatePassword(id uint64, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.hosts[id]
	if !found {
		return errors.New("not found")
	}
	password = strings.TrimSpace(password)
	if s.box != nil && password != "" {
		if enc, err := s.box.Encrypt(password); err == nil {
			s.passwords[id] = enc
			h.HasPassword = true
		}
	} else if password == "" {
		delete(s.passwords, id)
		h.HasPassword = false
	}
	h.UpdatedAt = time.Now()
	return s.save()
}

func (s *FileVPSStore) GetCredentials(id uint64) (*Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	pass := ""
	if enc, exists := s.passwords[id]; exists && s.box != nil {
		if plain, err := s.box.Decrypt(enc); err == nil {
			pass = plain
		}
	}
	return &Credentials{
		VPSID:       h.ID,
		Name:        h.Name,
		IP:          h.IP,
		SSHPort:     h.SSHPort,
		SSHUsername: h.SSHUsername,
		SSHPassword: pass,
		Domain:      h.Domain,
	}, nil
}
