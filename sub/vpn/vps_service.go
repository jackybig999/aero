// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EndpointInfo is the harvested AERO Edge configuration for subscription builders.
type EndpointInfo struct {
	VPSID     uint64    `json:"vps_id"`
	Name      string    `json:"name"`
	Region    string    `json:"region,omitempty"`
	Host      string    `json:"host"`
	IP        string    `json:"ip,omitempty"`
	Port      int       `json:"port"`
	SubSecret string    `json:"sub_secret"`
	AdminKey  string    `json:"admin_key"`
	HasAdmin  bool      `json:"has_admin"`
	SubURL    string    `json:"sub_url"`
	Installed bool      `json:"installed"`
	Version   string    `json:"version,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EndpointStore persists harvested endpoints into aero_endpoints.json.
type EndpointStore struct {
	mu    sync.RWMutex
	path  string
	items map[uint64]EndpointInfo
}

type endpointSnapshot struct {
	Items []EndpointInfo `json:"items"`
}

func NewEndpointStore(path string) (*EndpointStore, error) {
	if path == "" {
		path = filepath.Join("data", "aero_endpoints.json")
	}
	es := &EndpointStore{
		path:  path,
		items: make(map[uint64]EndpointInfo),
	}
	_ = es.load()
	return es, nil
}

func (s *EndpointStore) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var snap endpointSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range snap.Items {
		s.items[it.VPSID] = it
	}
	return nil
}

func (s *EndpointStore) persistLocked() error {
	snap := endpointSnapshot{Items: make([]EndpointInfo, 0, len(s.items))}
	for _, it := range s.items {
		snap.Items = append(snap.Items, it)
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *EndpointStore) Upsert(ep EndpointInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep.UpdatedAt = time.Now()
	s.items[ep.VPSID] = ep
	return s.persistLocked()
}

func (s *EndpointStore) Delete(vpsID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, vpsID)
	return s.persistLocked()
}

func (s *EndpointStore) Get(vpsID uint64) (EndpointInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ep, ok := s.items[vpsID]
	return ep, ok
}

func (s *EndpointStore) List() []EndpointInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]EndpointInfo, 0, len(s.items))
	for _, ep := range s.items {
		out = append(out, ep)
	}
	return out
}

// VPSService orchestrates VPS machine asset lifecycle.
type VPSService struct {
	store VPSStore
	box     *SecretBox
	eps     *EndpointStore
	nodeSvc *NodeService
}

func NewVPSService(s VPSStore, box *SecretBox, eps *EndpointStore) *VPSService {
	return &VPSService{store: s, box: box, eps: eps}
}

func (s *VPSService) SetNodeService(ns *NodeService) {
	s.nodeSvc = ns
}

func (s *VPSService) Create(p CreateVPSParams) (*VPSHost, error) {
	p.IP = strings.TrimSpace(p.IP)
	p.Name = strings.TrimSpace(p.Name)
	p.SSHPassword = strings.TrimSpace(p.SSHPassword)
	p.SSHUsername = strings.TrimSpace(p.SSHUsername)
	p.Domain = strings.TrimSpace(p.Domain)
	if p.Name == "" || p.IP == "" {
		return nil, fmt.Errorf("name and ip required")
	}
	if p.Domain == "" {
		return nil, fmt.Errorf("域名为必填项：严禁未绑定域名的 VPS 接入中台，杜绝源站 IP 泄露")
	}
	if net.ParseIP(p.Domain) != nil || !strings.Contains(p.Domain, ".") {
		return nil, fmt.Errorf("域名格式不合法：%s 不是有效的公网域名（严禁使用纯 IP 作为域名）", p.Domain)
	}

	if p.SSHPort <= 0 {
		p.SSHPort = 22
	}
	if p.SSHUsername == "" {
		p.SSHUsername = "root"
	}
	if p.Role == "" {
		p.Role = "node"
	}
	if p.SSHPassword == "" {
		return nil, fmt.Errorf("ssh_password required")
	}
	host, err := s.store.Create(p)
	if err != nil {
		return nil, err
	}

	// 自动联动创建/同步至代理节点注册表，杜绝不同步与残留
	if s.nodeSvc != nil && host != nil {
		targetHost := host.Domain
		if targetHost == "" {
			targetHost = host.IP
		}
		_, _ = s.nodeSvc.CreateNode(host.Name, host.Role, targetHost, "aero-h2", 443, 500, false, 100, host.ID)
	}
	return host, nil
}

func (s *VPSService) List() ([]*VPSHost, error)     { return s.store.List() }
func (s *VPSService) Get(id uint64) (*VPSHost, error) { return s.store.Get(id) }

func (s *VPSService) Delete(id uint64) error {
	vps, _ := s.store.Get(id)
	ip := ""
	if vps != nil {
		ip = vps.IP
	}
	err := s.store.Delete(id)
	if err == nil {
		if s.eps != nil {
			_ = s.eps.Delete(id)
		}
		if s.nodeSvc != nil {
			// 级联彻底清理关联节点与订阅，绝不残留失联孤儿
			_, _ = s.nodeSvc.DeleteMatching(id, ip)
		}
	}
	return err
}

func (s *VPSService) UpdateMeta(id uint64, p UpdateVPSParams) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Role = strings.TrimSpace(p.Role)
	p.Remark = strings.TrimSpace(p.Remark)
	p.SSHUsername = strings.TrimSpace(p.SSHUsername)
	_, err := s.store.Update(id, p)
	return err
}

func (s *VPSService) UpdatePassword(id uint64, password string) error {
	return s.store.UpdatePassword(id, password)
}

func (s *VPSService) UpdateDomain(id uint64, domain string) error {
	domain = strings.TrimSpace(domain)
	err := s.store.UpdateDomain(id, domain)
	if err == nil {
		if s.nodeSvc != nil && domain != "" {
			s.nodeSvc.UpdateHostByVPS(id, domain)
		}
		if s.eps != nil && domain != "" {
			if ep, ok := s.eps.Get(id); ok {
				ep.Host = domain
				sec := ep.SubSecret
				if sec == "" {
					sec = "superadmin"
				}
				ep.SubURL = fmt.Sprintf("https://%s/sub/%s", domain, sec)
				_ = s.eps.Upsert(ep)
			}
		}
	}
	return err
}

func (s *VPSService) GetCredentials(id uint64) (*Credentials, error) {
	return s.store.GetCredentials(id)
}

// CalculateCapacity assesses health score (0~100) and capacity tier.
func CalculateCapacity(m *HostMetrics) (score int, tier int, state string) {
	if m == nil || !m.ProbeOK {
		return 0, 1, "offline"
	}
	tier = 2
	if m.MemTotalMB > 0 {
		if m.MemTotalMB <= 1200 {
			tier = 1 // Nano/Edge (<=1GB)
		} else if m.MemTotalMB > 4500 {
			tier = 3 // Enterprise (>4GB)
		}
	}

	s := 100.0
	if m.MemPercent > 90 {
		s -= 45
	} else if m.MemPercent > 80 {
		s -= 30
	} else if m.MemPercent > 70 {
		s -= 15
	}

	if m.CPUPercent > 90 {
		s -= 40
	} else if m.CPUPercent > 75 {
		s -= 25
	} else if m.CPUPercent > 50 {
		s -= 10
	}

	if m.LatencyMS > 400 {
		s -= 20
	} else if m.LatencyMS > 250 {
		s -= 10
	} else if m.LatencyMS > 150 {
		s -= 5
	}

	if s < 0 {
		s = 0
	}
	score = int(s)

	switch {
	case score >= 80:
		state = "excellent"
	case score >= 60:
		state = "good"
	case score >= 40:
		state = "heavy"
	default:
		state = "overload"
	}
	return score, tier, state
}

func (s *VPSService) VerifyOrSyncDomain(ctx context.Context, domain, ip string) error {
	domain = strings.TrimSpace(domain)
	ip = strings.TrimSpace(ip)
	if domain == "" || ip == "" {
		return fmt.Errorf("domain and ip required")
	}
	// 本地回环直接放行测试
	if domain == "localhost" || domain == "127.0.0.1" {
		return nil
	}
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("域名 %s 尚未在公网解析，请添加 A 记录指向 %s", domain, ip)
	}
	for _, resolved := range ips {
		if resolved.String() == ip {
			return nil
		}
	}
	return fmt.Errorf("域名 %s 当前解析出的 IP (%v) 与 VPS IP (%s) 不一致", domain, ips, ip)
}
