// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ==========================================
// 1. Connection Limiter (Multi-tenant & Global)
// ==========================================

const (
	DefaultMaxGlobal = 4096 // Global active tunnel connection limit
	DefaultMaxPerTok = 1024 // Per-token connection limit
)

// ConnLimiter manages concurrent connections globally and per token
type ConnLimiter struct {
	maxGlobal int64
	maxPerTok int64

	global atomic.Int64

	mu     sync.Mutex
	perTok map[string]int64
}

// NewConnLimiter creates a new ConnLimiter
func NewConnLimiter(maxGlobal, maxPerTok int) *ConnLimiter {
	if maxGlobal <= 0 {
		maxGlobal = DefaultMaxGlobal
	}
	if maxPerTok <= 0 {
		maxPerTok = DefaultMaxPerTok
	}
	return &ConnLimiter{
		maxGlobal: int64(maxGlobal),
		maxPerTok: int64(maxPerTok),
		perTok:    make(map[string]int64),
	}
}

// TryAcquire attempts to acquire a connection slot for the given token.
// Returns false if global limit or per-token limit is exceeded.
func (l *ConnLimiter) TryAcquire(token string) bool {
	if token == "" {
		return false
	}
	// Global limit CAS
	for {
		cur := l.global.Load()
		if cur >= l.maxGlobal {
			return false
		}
		if l.global.CompareAndSwap(cur, cur+1) {
			break
		}
	}

	l.mu.Lock()
	n := l.perTok[token]
	if n >= l.maxPerTok {
		l.mu.Unlock()
		l.global.Add(-1)
		return false
	}
	l.perTok[token] = n + 1
	l.mu.Unlock()
	return true
}

// Release releases a connection slot for the given token.
func (l *ConnLimiter) Release(token string) {
	if token == "" {
		return
	}
	l.mu.Lock()
	if n, ok := l.perTok[token]; ok {
		if n <= 1 {
			delete(l.perTok, token)
		} else {
			l.perTok[token] = n - 1
		}
	}
	l.mu.Unlock()
	l.global.Add(-1)
}

// Active returns current global active count
func (l *ConnLimiter) Active() int64 {
	return l.global.Load()
}

// ActiveToken returns active count for a specific token
func (l *ConnLimiter) ActiveToken(token string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perTok[token]
}

// MaxGlobal returns maximum global limit
func (l *ConnLimiter) MaxGlobal() int64 { return l.maxGlobal }

// MaxPerTok returns maximum per-token limit
func (l *ConnLimiter) MaxPerTok() int64 { return l.maxPerTok }

// ==========================================
// 2. Bandwidth Limiter (Token Bucket per Token)
// ==========================================

// BandwidthLimiter limits bandwidth per token in bytes/second. 0 = unlimited.
type BandwidthLimiter struct {
	mu      sync.Mutex
	rate    float64 // bytes per second
	burst   float64
	buckets map[string]*bandwidthBucket
}

type bandwidthBucket struct {
	tokens float64
	last   time.Time
}

// NewBandwidthLimiter creates a BandwidthLimiter; bytesPerSec <= 0 disables limiting.
func NewBandwidthLimiter(bytesPerSec int) *BandwidthLimiter {
	if bytesPerSec <= 0 {
		return &BandwidthLimiter{rate: 0, buckets: make(map[string]*bandwidthBucket)}
	}
	r := float64(bytesPerSec)
	return &BandwidthLimiter{
		rate:    r,
		burst:   r * 2, // 2s burst capacity
		buckets: make(map[string]*bandwidthBucket),
	}
}

// Enabled returns true if bandwidth limiting is active
func (l *BandwidthLimiter) Enabled() bool {
	return l != nil && l.rate > 0
}

// Rate returns configured rate in bytes/sec
func (l *BandwidthLimiter) Rate() float64 {
	if l == nil {
		return 0
	}
	return l.rate
}

// TakeContext deducts n bytes; sleeps until available or until ctx is canceled
func (l *BandwidthLimiter) TakeContext(ctx context.Context, token string, n int) error {
	if l == nil || l.rate <= 0 || n <= 0 || token == "" {
		return nil
	}
	for {
		wait := l.tryTake(token, n)
		if wait <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// Take deducts n bytes; sleeps until available if rate exceeded (backward compatibility wrapper)
func (l *BandwidthLimiter) Take(token string, n int) {
	_ = l.TakeContext(context.Background(), token, n)
}

func (l *BandwidthLimiter) tryTake(token string, n int) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[token]
	if !ok {
		b = &bandwidthBucket{tokens: l.burst, last: now}
		l.buckets[token] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	need := float64(n)
	if b.tokens >= need {
		b.tokens -= need
		return 0
	}
	deficit := need - b.tokens
	b.tokens = 0
	sec := deficit / l.rate
	if sec < 0.001 {
		sec = 0.001
	}
	return time.Duration(sec * float64(time.Second))
}

// ==========================================
// 3. Dial Guard & SSRF Protection
// ==========================================

// IsBlockedTarget returns true if target must not be dialed (loopback, private, CGNAT, etc.)
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
		return false, ""
	}
	return IsBlockedIP(ip)
}

// IsBlockedIP returns true if IP is loopback, private, link-local, unspecified, or CGNAT.
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

// DialGuard provides concurrency limiting, SSRF protection, and intelligent Cloudflare WARP upstream routing
type DialGuard struct {
	sem          chan struct{}
	AllowLocal   bool
	WarpProxy    string // e.g. "127.0.0.1:40000"
	WarpAll      bool   // route all outbound traffic through WARP proxy
	warpHealthy  atomic.Bool
	probeTrigger chan struct{}
	stopCh       chan struct{}
	closeOnce    sync.Once
}

// NewDialGuard creates a DialGuard; maxConcurrent <= 0 defaults to 256
func NewDialGuard(maxConcurrent int) *DialGuard {
	if maxConcurrent <= 0 {
		maxConcurrent = 256
	}
	dg := &DialGuard{
		sem:          make(chan struct{}, maxConcurrent),
		probeTrigger: make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
	}
	dg.warpHealthy.Store(true)
	go dg.backgroundWarpHealthChecker()
	return dg
}

// Close gracefully stops the background WARP health checker
func (g *DialGuard) Close() {
	if g != nil {
		g.closeOnce.Do(func() {
			close(g.stopCh)
		})
	}
}

// SetWarpProxy configures upstream Cloudflare WARP SOCKS5 proxy
func (g *DialGuard) SetWarpProxy(proxyAddr string, all bool) {
	if g != nil {
		g.WarpProxy = proxyAddr
		g.WarpAll = all
		if proxyAddr != "" {
			select {
			case g.probeTrigger <- struct{}{}:
			default:
			}
		}
	}
}

// DialTimeout dials with concurrency limiting, SSRF protection, and WARP unblocking
func (g *DialGuard) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	dialFn := safeDial
	if g != nil && g.AllowLocal {
		dialFn = net.DialTimeout
	}

	isAIDomain := isTargetAIDomain(address)

	// 智能 WARP 出口净化：当配置/探测到远端 VPS 运行了 Cloudflare WARP SOCKS5 代理时，
	// 对 Google、OpenAI、Gemini 等 AI 限制域名（或全量流量）经由 WARP 出口转发，彻底消灭 IP 标记与 403 封锁！
	if g != nil && g.WarpProxy != "" && (g.WarpAll || isAIDomain) {
		if g.warpHealthy.Load() {
			c, err := dialViaSOCKS5(g.WarpProxy, address, timeout)
			if err == nil {
				return c, nil
			}
			g.warpHealthy.Store(false)
			select {
			case g.probeTrigger <- struct{}{}:
			default:
			}
			log.Printf("[WARP-CIRCUIT-OPEN] Upstream WARP dial failed for %s (%v). Circuit tripped.", address, err)
		}

		// AI 核心资产 Fail-Closed 保护：0ms 立即阻断，绝不直连裸奔！
		if isAIDomain {
			return nil, fmt.Errorf("AERO_WARP_FAIL_CLOSED: direct dial refused to prevent AI region leak (target: %s)", address)
		}

		log.Printf("[WARP-FALLBACK] Non-AI target %s dial via direct due to open circuit.", address)
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

func (g *DialGuard) backgroundWarpHealthChecker() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
		case <-g.probeTrigger:
		}

		if g.WarpProxy == "" {
			continue
		}

		probeConn, err := net.DialTimeout("tcp", g.WarpProxy, 1500*time.Millisecond)
		if err == nil {
			_ = probeConn.Close()
			if !g.warpHealthy.Load() {
				log.Printf("[WARP-CIRCUIT-RESET] WARP proxy %s recovered. Normal routing restored.", g.WarpProxy)
				g.warpHealthy.Store(true)
			}
		}
	}
}

func isTargetAIDomain(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	aiSuffixes := []string{
		"google.com",
		"googleapis.com",
		"gstatic.com",
		"googleusercontent.com",
		"ggpht.com",
		"youtube.com",
		"ytimg.com",
		"openai.com",
		"chatgpt.com",
		"oaistatic.com",
		"oaiusercontent.com",
		"anthropic.com",
		"claude.ai",
		"ai.google.dev",
		"makersuite.google.com",
		"deepmind.google",
		"bing.com",
		"copilot.microsoft.com",
	}

	for _, suffix := range aiSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func dialViaSOCKS5(proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid port in %s", targetAddr)
	}

	// 1. SOCKS5 握手: 客户端问候 [VER=5, NMETHODS=1, METHOD=0 (No Auth)]
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 greeting failed: %w", err)
	}

	// 读取服务端选择
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 auth resp failed: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: 0x%02x", resp[1])
	}

	// 2. CONNECT 请求 [VER=5, CMD=1 (CONNECT), RSV=0, ATYP=..., DST.ADDR, DST.PORT]
	var req []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = make([]byte, 4+net.IPv4len+2)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x01 // IPv4
		copy(req[4:4+net.IPv4len], ip4)
		binary.BigEndian.PutUint16(req[4+net.IPv4len:], uint16(port))
	} else if ip6 := ip.To16(); ip6 != nil {
		req = make([]byte, 4+net.IPv6len+2)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x04 // IPv6
		copy(req[4:4+net.IPv6len], ip6)
		binary.BigEndian.PutUint16(req[4+net.IPv6len:], uint16(port))
	} else {
		// 域名 (FQDN)
		if len(host) > 255 {
			_ = conn.Close()
			return nil, fmt.Errorf("domain name too long: %s", host)
		}
		req = make([]byte, 4+1+len(host)+2)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x03 // Domain name
		req[4] = byte(len(host))
		copy(req[5:5+len(host)], host)
		binary.BigEndian.PutUint16(req[5+len(host):], uint16(port))
	}

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect request failed: %w", err)
	}

	// 3. 读取连接响应 [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
	connResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, connResp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect resp header failed: %w", err)
	}
	if connResp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect rejected by upstream: 0x%02x", connResp[1])
	}

	// 消费剩余的绑定地址
	switch connResp[3] {
	case 0x01: // IPv4
		bnd := make([]byte, 4+2)
		_, _ = io.ReadFull(conn, bnd)
	case 0x04: // IPv6
		bnd := make([]byte, 16+2)
		_, _ = io.ReadFull(conn, bnd)
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenBuf)
		bnd := make([]byte, int(lenBuf[0])+2)
		_, _ = io.ReadFull(conn, bnd)
	}

	// 连接成功后清除滑动 deadline，恢复长连接全双工通信
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
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

// Cap returns concurrency capacity
func (g *DialGuard) Cap() int {
	if g == nil || g.sem == nil {
		return 0
	}
	return cap(g.sem)
}

// ==========================================
// 4. Rate Limiter (IP Connection Rate & Ban)
// ==========================================

// RateLimiter limits incoming connection rates per IP and manages temporary bans
type RateLimiter struct {
	mu            sync.Mutex
	buckets       map[string]*rateTokenBucket
	maxPerIP      float64
	banAfter      int
	banDuration   time.Duration
	bans          map[string]time.Time
	fails         map[string]int
	lastSweep     time.Time
	lastSweepUnix atomic.Int64
}

type rateTokenBucket struct {
	tokens   float64
	lastTime time.Time
	rate     float64
	max      float64
}

// NewRateLimiter creates a RateLimiter; maxConnsPerIPPerSec <= 0 defaults to 200
func NewRateLimiter(maxConnsPerIPPerSec int) *RateLimiter {
	if maxConnsPerIPPerSec <= 0 {
		maxConnsPerIPPerSec = 200
	}
	return &RateLimiter{
		buckets:     make(map[string]*rateTokenBucket),
		maxPerIP:    float64(maxConnsPerIPPerSec),
		banAfter:    20,
		banDuration: 10 * time.Minute,
		bans:        make(map[string]time.Time),
		fails:       make(map[string]int),
		lastSweep:   time.Now(),
	}
}

// ClientIP extracts IP from HTTP request using physical RemoteAddr
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Allow returns true if IP is allowed to connect
func (l *RateLimiter) Allow(ip string) bool {
	nowUnix := time.Now().Unix()
	// 锁外无锁检查：若距上次清理不足 120 秒，绝不进锁全量清扫！ (NEW-04)
	if nowUnix-l.lastSweepUnix.Load() > 120 {
		if l.lastSweepUnix.CompareAndSwap(l.lastSweepUnix.Load(), nowUnix) {
			l.mu.Lock()
			l.sweepLocked()
			l.mu.Unlock()
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if until, ok := l.bans[ip]; ok {
		if time.Now().Before(until) {
			return false
		}
		delete(l.bans, ip)
		delete(l.fails, ip)
	}

	now := time.Now()
	b, ok := l.buckets[ip]
	if !ok {
		l.buckets[ip] = &rateTokenBucket{
			tokens:   l.maxPerIP - 1,
			lastTime: now,
			rate:     l.maxPerIP,
			max:      l.maxPerIP,
		}
		return true
	}
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.lastTime = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RecordFail increments failure count and bans IP if threshold exceeded
func (l *RateLimiter) RecordFail(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[ip]++
	if l.fails[ip] >= l.banAfter {
		l.bans[ip] = time.Now().Add(l.banDuration)
		l.fails[ip] = 0
		return true
	}
	return false
}

// IsBanned returns true if IP is currently banned
func (l *RateLimiter) IsBanned(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.bans[ip]
	return ok && time.Now().Before(until)
}

func (l *RateLimiter) sweepLocked() {
	if time.Since(l.lastSweep) < 2*time.Minute {
		return
	}
	l.lastSweep = time.Now()
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, b := range l.buckets {
		if b.lastTime.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
	now := time.Now()
	for k, until := range l.bans {
		if now.After(until) {
			delete(l.bans, k)
		}
	}
}
