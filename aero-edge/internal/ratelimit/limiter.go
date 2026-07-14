// Package ratelimit：单 IP 新连接速率 + 认证失败封禁，保护订阅/多用户场景。
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter 新连接速率限制（非隧道字节限速）。
type Limiter struct {
	mu          sync.Mutex
	buckets     map[string]*tokenBucket
	maxPerIP    float64
	banAfter    int
	banDuration time.Duration
	bans        map[string]time.Time
	fails       map[string]int
	lastSweep   time.Time
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
	rate     float64
	max      float64
}

// New 创建限制器。maxConnsPerIPPerSec≤0 时默认 20（多用户 NAT 友好，防扫）。
func New(maxConnsPerIPPerSec int) *Limiter {
	if maxConnsPerIPPerSec <= 0 {
		maxConnsPerIPPerSec = 20
	}
	return &Limiter{
		buckets:     make(map[string]*tokenBucket),
		maxPerIP:    float64(maxConnsPerIPPerSec),
		banAfter:    20,
		banDuration: 10 * time.Minute,
		bans:        make(map[string]time.Time),
		fails:       make(map[string]int),
		lastSweep:   time.Now(),
	}
}

// ClientIP 从请求提取客户端 IP。
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

// Allow 是否允许该 IP 发起新 CONNECT。
func (l *Limiter) Allow(ip string) bool {
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
		l.buckets[ip] = &tokenBucket{
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

// RecordFail 认证失败计数；返回是否刚触发封禁。
func (l *Limiter) RecordFail(ip string) bool {
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

// IsBanned 是否在封禁期。
func (l *Limiter) IsBanned(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.bans[ip]
	return ok && time.Now().Before(until)
}

func (l *Limiter) sweepLocked() {
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
