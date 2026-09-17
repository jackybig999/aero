// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package traffic 限制同时拨号数，保护小 VPS 的 fd/CPU。
// 仅限制 Dial 瞬间并发，连接建立后立即释放槽位。
// 同时提供 IsBlockedTarget，拒绝 CONNECT 到私网/环回（防 SSRF 与代理环路）。
package traffic

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// IsBlockedTarget returns true if CONNECT target must not be dialed by edge.
// Blocks loopback, private RFC1918, link-local, unspecified, CGNAT 100.64/10.
func IsBlockedTarget(target string) (bool, string) {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimSpace(host)
	if host == "" {
		return true, "empty host"
	}
	low := strings.ToLower(host)
	if low == "localhost" || low == "localhost." {
		return true, "localhost"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// hostname: allow (public DNS); private names are rare on edge
		return false, ""
	}
	return IsBlockedIP(ip)
}

// IsBlockedIP returns true if ip must not be dialed by edge (loopback, private, link-local, unspecified, CGNAT).
func IsBlockedIP(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "nil ip"
	}
	if ip.IsLoopback() {
		return true, "loopback"
	}
	if ip.IsPrivate() {
		return true, "private"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true, "link-local"
	}
	if ip.IsUnspecified() {
		return true, "unspecified"
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true, "cgnat"
		}
	}
	return false, ""
}

// DialGuard 并发 dial 闸门。
type DialGuard struct {
	sem        chan struct{}
	AllowLocal bool
}

type Guard = DialGuard

// NewDialGuard maxConcurrent≤0 时默认 256。
func NewDialGuard(maxConcurrent int) *DialGuard {
	if maxConcurrent <= 0 {
		maxConcurrent = 256
	}
	return &DialGuard{sem: make(chan struct{}, maxConcurrent)}
}

// DialTimeout 占用槽位拨号，返回后释放槽（无论成败）。同时默认通过 safeDial 防止私网与 DNS 重绑定。
func (g *DialGuard) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	dialFn := safeDial
	if g != nil && g.AllowLocal {
		dialFn = net.DialTimeout
	}
	if g == nil || g.sem == nil {
		return dialFn(network, address, timeout)
	}
	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
	case <-time.After(timeout):
		return nil, fmt.Errorf("dial queue full")
	}
	return dialFn(network, address, timeout)
}

func safeDial(network, address string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err == nil {
				if ip := net.ParseIP(host); ip != nil {
					if blocked, why := IsBlockedIP(ip); blocked {
						return fmt.Errorf("blocked target IP %s (%s)", ip, why)
					}
				}
			}
			return nil
		},
	}
	return d.Dial(network, address)
}

// Cap 并发上限。
func (g *DialGuard) Cap() int {
	if g == nil || g.sem == nil {
		return 0
	}
	return cap(g.sem)
}
