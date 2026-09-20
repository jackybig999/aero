// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// DefaultProtocolCacheTTL 协议偏好缓存 24 小时
const DefaultProtocolCacheTTL = 24 * time.Hour

// ProtocolPreference 记录端点的协议探测结果与过期时间
type ProtocolPreference struct {
	Protocol  string    // "h3" (MASQUE) 或 "h2" (CONNECT)
	ExpiresAt time.Time // 过期时间戳
}

// ProtocolCache 24 小时协议偏好缓存
type ProtocolCache struct {
	mu    sync.RWMutex
	cache map[string]ProtocolPreference
}

// GlobalProtocolCache 全局默认协议偏好缓存
var GlobalProtocolCache = NewProtocolCache()

// NewProtocolCache 创建协议缓存
func NewProtocolCache() *ProtocolCache {
	return &ProtocolCache{
		cache: make(map[string]ProtocolPreference),
	}
}

// Get 查询端点的已缓存协议；若未命中或已过期则返回空
func (c *ProtocolCache) Get(endpoint string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pref, ok := c.cache[endpoint]
	if !ok {
		return ""
	}
	if time.Now().After(pref.ExpiresAt) {
		return ""
	}
	return pref.Protocol
}

// Set 记录端点优选协议（默认 24 小时有效）
func (c *ProtocolCache) Set(endpoint, proto string, ttl ...time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	duration := DefaultProtocolCacheTTL
	if len(ttl) > 0 && ttl[0] > 0 {
		duration = ttl[0]
	}

	c.cache[endpoint] = ProtocolPreference{
		Protocol:  proto,
		ExpiresAt: time.Now().Add(duration),
	}
}

// Clear 清空缓存
func (c *ProtocolCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]ProtocolPreference)
}

// DialFunc 拨号闭包函数
type DialFunc func(ctx context.Context) (net.Conn, error)

// FallbackRacer 双栈竞速拨号器：支持 300ms 快速回退 H2 与 24h 缓存
type FallbackRacer struct {
	cache       *ProtocolCache
	raceTimeout time.Duration
}

// NewFallbackRacer 创建双栈竞速拨号器
func NewFallbackRacer(cache *ProtocolCache, raceTimeout ...time.Duration) *FallbackRacer {
	if cache == nil {
		cache = GlobalProtocolCache
	}
	timeout := 300 * time.Millisecond // 默认 300ms MASQUE 竞速窗口
	if len(raceTimeout) > 0 && raceTimeout[0] > 0 {
		timeout = raceTimeout[0]
	}
	return &FallbackRacer{
		cache:       cache,
		raceTimeout: timeout,
	}
}

// Dial 执行自适应双栈拨号：
// 1. 若 24h 缓存命中 "h2"，直接跳过 300ms 竞速直接走 H2；
// 2. 若未缓存，启动 MASQUE (H3) 拨号；若 300ms 内未成功或遭遇 UDP 阻断，立刻触发 H2 备用隧道；
// 3. 胜利者写入 24h 缓存，失败者连接被优雅关闭。
func (r *FallbackRacer) Dial(ctx context.Context, endpoint string, dialH3 DialFunc, dialH2 DialFunc) (net.Conn, string, error) {
	// 1. 检查 24h 协议缓存
	if cached := r.cache.Get(endpoint); cached == "h2" {
		conn, err := dialH2(ctx)
		if err == nil {
			return conn, "h2", nil
		}
		// H2 亦失败，降级清除缓存并继续完整竞速流程
		r.cache.Set(endpoint, "", -1)
	}

	type dialResult struct {
		conn     net.Conn
		protocol string
		err      error
	}

	resCh := make(chan dialResult, 2)
	h3Ctx, cancelH3 := context.WithCancel(ctx)
	defer cancelH3()

	// 启动 MASQUE (H3) 优先拨号
	go func() {
		conn, err := dialH3(h3Ctx)
		select {
		case resCh <- dialResult{conn: conn, protocol: "h3", err: err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	// 300ms 定时器
	timer := time.NewTimer(r.raceTimeout)
	defer timer.Stop()

	var h2Started bool
	var h2Ctx context.Context
	var cancelH2 context.CancelFunc

	startH2 := func() {
		if h2Started {
			return
		}
		h2Started = true
		h2Ctx, cancelH2 = context.WithCancel(ctx)
		go func() {
			conn, err := dialH2(h2Ctx)
			select {
			case resCh <- dialResult{conn: conn, protocol: "h2", err: err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}

	// 等待首个信号：300ms 超时或 H3 直接返回
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case res := <-resCh:
		if res.err == nil && res.conn != nil {
			// H3 极速成功
			r.cache.Set(endpoint, "h3")
			return res.conn, "h3", nil
		}
		// H3 遇阻，立刻启动 H2 回退
		startH2()
	case <-timer.C:
		// 300ms 超时未建连，并发启动 H2 抢跑
		startH2()
	}

	// 收集最终成功连接
	defer func() {
		if cancelH2 != nil {
			cancelH2()
		}
	}()

	var lastErr error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case res := <-resCh:
			if res.err == nil && res.conn != nil {
				// 胜出者：固化 24 小时协议偏好并返回
				r.cache.Set(endpoint, res.protocol)
				return res.conn, res.protocol, nil
			}
			lastErr = res.err
		}
	}

	if lastErr == nil {
		lastErr = errors.New("all protocol dialers failed")
	}
	return nil, "", fmt.Errorf("fallback dial failed: %w", lastErr)
}
