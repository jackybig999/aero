// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package traffic 限制全局与每 token 并发隧道数，防止小 VPS 被拖垮。
package traffic

import (
	"sync"
	"sync/atomic"
)

// Defaults 面向「单 VPS 多用户」的保守默认值。
const (
	DefaultMaxGlobal = 4096 // 全局活跃 CONNECT 上限
	DefaultMaxPerTok = 1024 // 单 token 上限（订阅用户，彻底规避 Wi-Fi 切换并发重连 503 满载拒连）
)

// ConnLimiter 并发连接限制。
type ConnLimiter struct {
	maxGlobal int64
	maxPerTok int64

	global atomic.Int64

	mu     sync.Mutex
	perTok map[string]int64
}

// NewConnLimiter 创建限制器；maxGlobal/maxPerTok ≤0 时使用默认值。
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

// TryAcquire 尝试占用一条隧道。ok=false 时不要进入中继。
func (l *ConnLimiter) TryAcquire(token string) (ok bool) {
	if token == "" {
		return false
	}
	// 先全局 CAS，失败则拒绝
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

// Release 释放一条隧道。
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

// Active 当前全局活跃数。
func (l *ConnLimiter) Active() int64 {
	return l.global.Load()
}

// ActiveToken 某 token 活跃数。
func (l *ConnLimiter) ActiveToken(token string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perTok[token]
}

// MaxGlobal / MaxPerTok 配置值。
func (l *ConnLimiter) MaxGlobal() int64 { return l.maxGlobal }
func (l *ConnLimiter) MaxPerTok() int64 { return l.maxPerTok }
