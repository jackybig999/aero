// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// SSRFBlockedCIDRs 硬编码阻断的私有网段与云元数据地址 (Rule Phase 4.2)
var SSRFBlockedCIDRs = []string{
	"127.0.0.0/8",        // Loopback
	"10.0.0.0/8",         // RFC 1918 Class A
	"172.16.0.0/12",      // RFC 1918 Class B
	"192.168.0.0/16",     // RFC 1918 Class C
	"169.254.169.254/32", // AWS / GCP / Azure / Aliyun 云主机元数据服务
	"169.254.0.0/16",     // Link-local
	"0.0.0.0/8",          // Current network
	"::1/128",            // IPv6 Loopback
	"fc00::/7",           // IPv6 Unique Local
	"fe80::/10",          // IPv6 Link-local
}

// AuthGuard 服务端安全守卫：硬编码 SSRF 拦截与 Token 并发配额管控
type AuthGuard struct {
	blockedNets []*net.IPNet
	mu          sync.RWMutex
	activeSlots map[string]*atomic.Int32
	maxPerToken int32
}

// NewAuthGuard 创建安全守卫
func NewAuthGuard(maxPerToken ...int32) *AuthGuard {
	limit := int32(100)
	if len(maxPerToken) > 0 && maxPerToken[0] > 0 {
		limit = maxPerToken[0]
	}

	var parsedNets []*net.IPNet
	for _, cidr := range SSRFBlockedCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			parsedNets = append(parsedNets, ipNet)
		}
	}

	return &AuthGuard{
		blockedNets: parsedNets,
		activeSlots: make(map[string]*atomic.Int32),
		maxPerToken: limit,
	}
}

// CheckSSRF 严格检测目标地址是否命中美云元数据或内网私网地址 (硬编码 SSRF 拦截)
func (g *AuthGuard) CheckSSRF(target string) error {
	target = strings.TrimSpace(target)
	if idx := strings.Index(target, "://"); idx != -1 {
		target = target[idx+3:]
	}
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("empty target host")
	}

	// 1. 若为直接 IP
	if ip := net.ParseIP(host); ip != nil {
		return g.checkIPBlocked(ip)
	}

	// 2. 本地回环主机名硬阻断
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "ip6-localhost" || lower == "ip6-loopback" || strings.HasSuffix(lower, ".local") {
		return fmt.Errorf("SSRF blocked: prohibited local hostname %s", host)
	}

	// 3. 解析 DNS 检查解析出的真实 IP 是否指向内网
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if err := g.checkIPBlocked(ip); err != nil {
				return fmt.Errorf("SSRF blocked: host %s resolves to forbidden IP %s", host, ip.String())
			}
		}
	}
	return nil
}

func (g *AuthGuard) checkIPBlocked(ip net.IP) error {
	for _, netBlock := range g.blockedNets {
		if netBlock.Contains(ip) {
			return fmt.Errorf("SSRF blocked: target IP %s falls into prohibited subnet %s", ip.String(), netBlock.String())
		}
	}
	return nil
}

// AcquireSlot 尝试为 Token 申请一个并发转发槽位
func (g *AuthGuard) AcquireSlot(token string) bool {
	g.mu.Lock()
	slot, ok := g.activeSlots[token]
	if !ok {
		slot = &atomic.Int32{}
		g.activeSlots[token] = slot
	}
	g.mu.Unlock()

	cur := slot.Add(1)
	if cur > g.maxPerToken {
		slot.Add(-1)
		return false
	}
	return true
}

// ReleaseSlot 归还并发转发槽位
func (g *AuthGuard) ReleaseSlot(token string) {
	g.mu.RLock()
	slot, ok := g.activeSlots[token]
	g.mu.RUnlock()

	if ok && slot != nil {
		slot.Add(-1)
	}
}

// ActiveSlots 返回指定 Token 当前占用的槽位数
func (g *AuthGuard) ActiveSlots(token string) int32 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if slot, ok := g.activeSlots[token]; ok {
		return slot.Load()
	}
	return 0
}
