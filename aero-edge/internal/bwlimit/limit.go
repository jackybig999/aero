// Package bwlimit 按 token 的简单字节速率限制（多用户公平共享出口）。
package bwlimit

import (
	"sync"
	"time"
)

// Limiter 每 token 下行+上行合计速率（bytes/s）。0 = 不限制。
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // bytes per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New bytesPerSec≤0 表示关闭限速。
func New(bytesPerSec int) *Limiter {
	if bytesPerSec <= 0 {
		return &Limiter{rate: 0, buckets: make(map[string]*bucket)}
	}
	r := float64(bytesPerSec)
	return &Limiter{
		rate:    r,
		burst:   r * 2, // 2 秒突发
		buckets: make(map[string]*bucket),
	}
}

// Enabled 是否启用。
func (l *Limiter) Enabled() bool {
	return l != nil && l.rate > 0
}

// Rate 配置速率。
func (l *Limiter) Rate() float64 {
	if l == nil {
		return 0
	}
	return l.rate
}

// Take 消费 n 字节；超速时 sleep 到可用（阻塞，简单可靠）。
func (l *Limiter) Take(token string, n int) {
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

func (l *Limiter) tryTake(token string, n int) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[token]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
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
