// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package edgepool 实现多 Edge 节点调度与故障自动切换。
// 设计约束（Step1 固化）：
//   - 配置的 Address 永不因探测改写端口（避免 18443 被误改成 443）
//   - 探测仅更新 Reachable / RTT / Results，供调度参考
package edgepool

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Server 表示一个 Edge 节点
type Server struct {
	Name string
	// Address 配置地址 host:port，探测不得改写
	Address   string
	Token     string
	SNI       string
	PinSPKI   []string
	Protocol  string
	Reachable bool
	RTT       time.Duration
	LastFail  time.Time
	FailCount int
	Results   []ProbeResult
}

// ServerConfig 节点配置参数
type ServerConfig struct {
	Name     string
	Address  string
	Token    string
	SNI      string
	PinSPKI  []string
	Protocol string
}

// Pool 管理多个 Edge 节点
type Pool struct {
	servers []*Server
	mu      sync.RWMutex
}

// New 从地址列表创建节点池（单个或逗号分隔）
func New(addresses string) (*Pool, error) {
	parts := splitAddresses(addresses)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no edge addresses provided")
	}
	servers := make([]*Server, 0, len(parts))
	for _, addr := range parts {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("invalid edge address %q: %w", addr, err)
		}
		servers = append(servers, &Server{Address: addr})
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no valid edge addresses")
	}
	return &Pool{servers: servers}, nil
}

// NewFromServers 从多节点详细配置列表构建节点池
func NewFromServers(cfgs []ServerConfig) (*Pool, error) {
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("no edge servers provided")
	}
	servers := make([]*Server, 0, len(cfgs))
	for _, cfg := range cfgs {
		addr := strings.TrimSpace(cfg.Address)
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("invalid edge address %q: %w", addr, err)
		}
		servers = append(servers, &Server{
			Name:     cfg.Name,
			Address:  addr,
			Token:    cfg.Token,
			SNI:      cfg.SNI,
			PinSPKI:  append([]string(nil), cfg.PinSPKI...),
			Protocol: cfg.Protocol,
		})
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no valid edge addresses")
	}
	return &Pool{servers: servers}, nil
}

// FindServer 根据地址获取节点详细信息副本
func (p *Pool) FindServer(addr string) *Server {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, s := range p.servers {
		if s != nil && s.Address == addr {
			cp := *s
			return &cp
		}
	}
	return nil
}

func splitAddresses(s string) []string {
	if strings.Contains(s, ",") {
		return strings.Split(s, ",")
	}
	return []string{s}
}

// ProbeAll 探测节点可达性。preferredPort 保留兼容；实际以各节点 Address 端口为准。
func (p *Pool) ProbeAll(preferredPort int) {
	_ = preferredPort
	var wg sync.WaitGroup
	p.mu.Lock()
	list := make([]*Server, len(p.servers))
	copy(list, p.servers)
	p.mu.Unlock()

	for _, s := range list {
		wg.Add(1)
		go func(srv *Server) {
			defer wg.Done()
			host, portStr, err := net.SplitHostPort(srv.Address)
			if err != nil {
				p.setProbeResult(srv.Address, false, 0, nil)
				return
			}
			var port int
			fmt.Sscanf(portStr, "%d", &port)

			pr := NewProbeWithPreferredPort(host, port)
			results := pr.Run()
			// 优先判定「配置端口」是否可达，避免被其它端口（如 443）抢走
			ok, rtt := configuredPortReachable(results, port)
			if !ok {
				// 配置端口不可达时，不改写 Address；整节点标为不可达
				p.setProbeResult(srv.Address, false, 0, results)
				return
			}
			p.setProbeResult(srv.Address, true, rtt, results)
		}(s)
	}
	wg.Wait()
}

func configuredPortReachable(results []ProbeResult, port int) (bool, time.Duration) {
	var best time.Duration
	found := false
	for _, r := range results {
		if !r.Reachable {
			continue
		}
		if int(r.Path.Port) != port {
			continue
		}
		if !found || r.RTT < best {
			best = r.RTT
			found = true
		}
	}
	return found, best
}

func (p *Pool) setProbeResult(addr string, reachable bool, rtt time.Duration, results []ProbeResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.servers {
		if s.Address == addr {
			s.Reachable = reachable
			s.RTT = rtt
			s.Results = results
			return
		}
	}
}

// SetProbeResult updates the reachable state and RTT for a server in the pool.
func (p *Pool) SetProbeResult(addr string, reachable bool, rtt time.Duration) {
	p.setProbeResult(addr, reachable, rtt, nil)
}

// Best 返回最优节点：可达优先 → RTT → 失败次数
func (p *Pool) Best() *Server {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	cooldown := 30 * time.Second
	candidates := make([]*Server, 0, len(p.servers))
	for _, s := range p.servers {
		if now.Sub(s.LastFail) > cooldown {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		candidates = append(candidates, p.servers...)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Reachable != candidates[j].Reachable {
			return candidates[i].Reachable && !candidates[j].Reachable
		}
		if candidates[i].RTT != candidates[j].RTT {
			return candidates[i].RTT < candidates[j].RTT
		}
		return candidates[i].FailCount < candidates[j].FailCount
	})
	return candidates[0]
}

// MarkFail 标记节点失败
func (p *Pool) MarkFail(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.servers {
		if s.Address == addr {
			s.LastFail = time.Now()
			s.FailCount++
			s.Reachable = false
			return
		}
	}
}

// AllAddresses 返回配置地址列表
func (p *Pool) AllAddresses() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, len(p.servers))
	for i, s := range p.servers {
		out[i] = s.Address
	}
	return out
}

// Count 节点数
func (p *Pool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.servers)
}

// NodeView 只读节点视图（供 API/UI）
type NodeView struct {
	Name      string
	Address   string
	Reachable bool
	RTT       time.Duration
	FailCount int
}

// Snapshot 返回节点只读快照（不改写 Address）
func (p *Pool) Snapshot() []NodeView {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]NodeView, len(p.servers))
	for i, s := range p.servers {
		out[i] = NodeView{
			Name:      s.Name,
			Address:   s.Address,
			Reachable: s.Reachable,
			RTT:       s.RTT,
			FailCount: s.FailCount,
		}
	}
	return out
}

// HasAddress 配置列表是否包含该地址
func (p *Pool) HasAddress(addr string) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, s := range p.servers {
		if s.Address == addr {
			return true
		}
	}
	return false
}
