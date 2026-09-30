// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"fmt"
	"net"
	"net/http"
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

// Take deducts n bytes; sleeps until available if rate exceeded
func (l *BandwidthLimiter) Take(token string, n int) {
	if l == nil || l.rate <= 0 || n <= 0 || token == "" {
		return
	}
	for {
		wait := l.tryTake(token, n)
		if wait <= 0 {
			return
		}
		time.Sleep(wait)
	}
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

// DialGuard limits instantaneous dial concurrency and prevents SSRF
type DialGuard struct {
	sem        chan struct{}
	AllowLocal bool
}

// NewDialGuard creates a DialGuard; maxConcurrent <= 0 defaults to 256
func NewDialGuard(maxConcurrent int) *DialGuard {
	if maxConcurrent <= 0 {
		maxConcurrent = 256
	}
	return &DialGuard{sem: make(chan struct{}, maxConcurrent)}
}

// DialTimeout dials with concurrency limiting and SSRF protection
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
	mu          sync.Mutex
	buckets     map[string]*rateTokenBucket
	maxPerIP    float64
	banAfter    int
	banDuration time.Duration
	bans        map[string]time.Time
	fails       map[string]int
	lastSweep   time.Time
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

// ClientIP extracts IP from HTTP request
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Allow returns true if IP is allowed to connect
func (l *RateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked()

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
