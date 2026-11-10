// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 验收项 1：被动感知健康检测
func TestSentinelPassiveHealth(t *testing.T) {
	sp := NewSessionPool()
	addr := "192.0.2.1:443"

	// 1. 空会话池：判定为不健康
	if isPassiveHealthy(addr, sp) {
		t.Fatalf("expected isPassiveHealthy to return false for empty session pool")
	}

	// 2. 空地址或空连接池
	if isPassiveHealthy("", sp) || isPassiveHealthy(addr, nil) {
		t.Fatalf("expected isPassiveHealthy to return false for empty addr or nil pool")
	}

	// 3. 活跃时间在 15s 内且连接有效
	c := &Client{}
	c.lastActive.Store(time.Now().UnixMilli())
	sp.mu.Lock()
	sp.clients[addr] = c
	sp.mu.Unlock()

	if !isPassiveHealthy(addr, sp) {
		t.Fatalf("expected isPassiveHealthy to return true for active connection within 15s")
	}

	// 4. 活跃时间超过 15s (20s 前)
	c.lastActive.Store(time.Now().Add(-20 * time.Second).UnixMilli())
	if isPassiveHealthy(addr, sp) {
		t.Fatalf("expected isPassiveHealthy to return false for connection idle > 15s")
	}

	// 5. mock 接口断言支持
	mockPool := &mockPassiveCheckerPool{healthy: true}
	if !isPassiveHealthy(addr, mockPool) {
		t.Fatalf("expected isPassiveHealthy to support passive checker interface")
	}
	mockPool.healthy = false
	if isPassiveHealthy(addr, mockPool) {
		t.Fatalf("expected isPassiveHealthy to return false when mock reports false")
	}
}

type mockPassiveCheckerPool struct {
	healthy bool
}

func (m *mockPassiveCheckerPool) Get(ctx context.Context, cfg *TransportConfig) (*Client, error) {
	return nil, nil
}
func (m *mockPassiveCheckerPool) Remove(addr string) {}
func (m *mockPassiveCheckerPool) Reset()             {}
func (m *mockPassiveCheckerPool) IsPassiveHealthy(addr string) bool {
	return m.healthy
}

// 验收项 2：主动探活（成功即 Close，严禁入池）
func TestSentinelActiveProbe(t *testing.T) {
	eng := NewEngine()
	eng.mu.Lock()
	eng.activeAddr = "192.0.2.10:443"
	eng.activeSNI = "node10.example.com"
	eng.mu.Unlock()

	sentinel := newNodeSentinel(eng)

	dialCalled := atomic.Int32{}
	var probedAddr, probedSNI string

	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		dialCalled.Add(1)
		probedAddr = cfg.Address
		probedSNI = cfg.TLSServerName
		return &Client{}, nil
	}

	ctx := context.Background()
	healthy := sentinel.isCurrentNodeHealthy(ctx)

	if !healthy {
		t.Fatalf("expected isCurrentNodeHealthy to return true on successful dial")
	}
	if dialCalled.Load() != 1 {
		t.Fatalf("expected dialFn to be called once, got %d", dialCalled.Load())
	}
	if probedAddr != "192.0.2.10:443" || probedSNI != "node10.example.com" {
		t.Fatalf("unexpected probe target: addr=%s, sni=%s", probedAddr, probedSNI)
	}

	// 严禁入池断言：sessionPool 中绝对不存在此节点
	if sp, ok := eng.sessionPool.(*SessionPool); ok {
		sp.mu.Lock()
		_, exists := sp.clients["192.0.2.10:443"]
		sp.mu.Unlock()
		if exists {
			t.Fatalf("probe client must NOT be added to session pool")
		}
	}

	// 探测失败场景
	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		return nil, errors.New("connection refused")
	}
	if sentinel.isCurrentNodeHealthy(ctx) {
		t.Fatalf("expected isCurrentNodeHealthy to return false on dial error")
	}
}

// 验收项 3：连续 3 次失败触发 Failover
func TestSentinelConsecutiveFailuresTriggerFailover(t *testing.T) {
	eng := NewEngine()

	applied := &Applied{
		Servers: []ServerConfig{
			{Name: "Node-1", Address: "192.0.2.1:443", Token: "tok1", SNI: "node1.example.com"},
			{Name: "Node-2", Address: "192.0.2.2:443", Token: "tok2", SNI: "node2.example.com"},
			{Name: "Node-3", Address: "192.0.2.3:443", Token: "tok3", SNI: "node3.example.com"},
		},
		Tokens: map[string]string{
			"192.0.2.1:443": "tok1",
			"192.0.2.2:443": "tok2",
			"192.0.2.3:443": "tok3",
		},
		SNIs: map[string]string{
			"192.0.2.1:443": "node1.example.com",
			"192.0.2.2:443": "node2.example.com",
			"192.0.2.3:443": "node3.example.com",
		},
	}

	if err := eng.Apply(applied); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if eng.activeAddr != "192.0.2.1:443" {
		t.Fatalf("expected initial active node to be Node-1, got %s", eng.activeAddr)
	}

	sentinel := newNodeSentinel(eng)

	// 配置探活行为：Node-1 挂掉，Node-2 正常
	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		if cfg.Address == "192.0.2.1:443" {
			return nil, errors.New("timeout")
		}
		if cfg.Address == "192.0.2.2:443" {
			return &Client{}, nil
		}
		return nil, errors.New("unreachable")
	}

	ctx := context.Background()

	// 第一次失败
	sentinel.check(ctx)
	if sentinel.failureCount != 1 {
		t.Fatalf("expected failureCount 1, got %d", sentinel.failureCount)
	}
	if eng.activeAddr != "192.0.2.1:443" {
		t.Fatalf("should not failover after 1st failure, activeAddr=%s", eng.activeAddr)
	}

	// 第二次失败
	sentinel.check(ctx)
	if sentinel.failureCount != 2 {
		t.Fatalf("expected failureCount 2, got %d", sentinel.failureCount)
	}
	if eng.activeAddr != "192.0.2.1:443" {
		t.Fatalf("should not failover after 2nd failure, activeAddr=%s", eng.activeAddr)
	}

	// 第三次失败：必须触发 Failover 切到 Node-2
	sentinel.check(ctx)
	if eng.activeAddr != "192.0.2.2:443" {
		t.Fatalf("expected active node switched to Node-2 (192.0.2.2:443), got %s", eng.activeAddr)
	}
	if sentinel.failureCount != 0 {
		t.Fatalf("expected failureCount reset to 0 after successful failover, got %d", sentinel.failureCount)
	}
	if sentinel.backoffIdx != 0 {
		t.Fatalf("expected backoffIdx reset to 0 after successful failover, got %d", sentinel.backoffIdx)
	}
}

// 验收项 4：指数退避与 wakeup 重置
func TestSentinelExponentialBackoffAndWakeup(t *testing.T) {
	eng := NewEngine()

	applied := &Applied{
		Servers: []ServerConfig{
			{Name: "Node-1", Address: "192.0.2.1:443", Token: "tok1"},
			{Name: "Node-2", Address: "192.0.2.2:443", Token: "tok2"},
		},
		Tokens: map[string]string{"192.0.2.1:443": "tok1", "192.0.2.2:443": "tok2"},
	}
	if err := eng.Apply(applied); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	sentinel := newNodeSentinel(eng)

	// 所有节点全部不可达
	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		return nil, errors.New("host unreachable")
	}

	ctx := context.Background()

	// 初始退避级别为 0
	if sentinel.backoffIdx != 0 {
		t.Fatalf("expected initial backoffIdx=0, got %d", sentinel.backoffIdx)
	}

	// 连续 3 次失败触发首次 failover，候选节点全失败 -> backoff 升级为 1 (30s)
	sentinel.check(ctx)
	sentinel.check(ctx)
	sentinel.check(ctx)
	if sentinel.backoffIdx != 1 {
		t.Fatalf("expected backoffIdx=1 (30s) after first failed failover, got %d", sentinel.backoffIdx)
	}

	// 再次触发 failover -> backoff 升级为 2 (60s)
	sentinel.failover(ctx)
	if sentinel.backoffIdx != 2 {
		t.Fatalf("expected backoffIdx=2 (60s), got %d", sentinel.backoffIdx)
	}

	// 再次触发 failover -> backoff 升级为 3 (120s)
	sentinel.failover(ctx)
	if sentinel.backoffIdx != 3 {
		t.Fatalf("expected backoffIdx=3 (120s), got %d", sentinel.backoffIdx)
	}

	// 再次触发 failover -> backoff 上限保持为 3 (120s)
	sentinel.failover(ctx)
	if sentinel.backoffIdx != 3 {
		t.Fatalf("expected backoffIdx capped at 3, got %d", sentinel.backoffIdx)
	}

	// 调用 wakeup() 重置退避与失败计数
	sentinel.wakeup()
	if sentinel.backoffIdx != 0 {
		t.Fatalf("expected backoffIdx reset to 0 after wakeup, got %d", sentinel.backoffIdx)
	}
	if sentinel.failureCount != 0 {
		t.Fatalf("expected failureCount reset to 0 after wakeup, got %d", sentinel.failureCount)
	}

	// 验证 wakeupCh 收到唤醒通知
	select {
	case <-sentinel.wakeupCh:
		// OK
	default:
		t.Fatalf("expected signal on wakeupCh after wakeup()")
	}
}

// 验收项 5：run 循环响应与后台自动 Failover
func TestSentinelRunLoopAndWakeup(t *testing.T) {
	eng := NewEngine()

	applied := &Applied{
		Servers: []ServerConfig{
			{Name: "Node-1", Address: "192.0.2.1:443", Token: "tok1"},
			{Name: "Node-2", Address: "192.0.2.2:443", Token: "tok2"},
		},
		Tokens: map[string]string{"192.0.2.1:443": "tok1", "192.0.2.2:443": "tok2"},
	}
	_ = eng.Apply(applied)

	sentinel := newNodeSentinel(eng)
	sentinel.checkInterval = 10 * time.Millisecond
	sentinel.backoffDurations = []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
	}

	// Node-1 挂掉，Node-2 正常
	sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		if cfg.Address == "192.0.2.1:443" {
			return nil, errors.New("timeout")
		}
		return &Client{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go sentinel.run(ctx)

	// 等待哨兵自动完成 3 次探活并切至 Node-2
	deadline := time.Now().Add(500 * time.Millisecond)
	switched := false
	for time.Now().Before(deadline) {
		eng.mu.RLock()
		addr := eng.activeAddr
		eng.mu.RUnlock()
		if addr == "192.0.2.2:443" {
			switched = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !switched {
		t.Fatalf("expected background sentinel loop to switch to Node-2")
	}

	// 测试 wakeup 唤醒
	sentinel.wakeup()

	// 退出验证
	cancel()
	time.Sleep(30 * time.Millisecond)
}

// 验收项 6：onNetworkChange 安全唤醒 Sentinel 并杜绝数据竞态
func TestEngineOnNetworkChangeTriggersSentinelWakeup(t *testing.T) {
	eng := NewEngine()

	sentinel := newNodeSentinel(eng)
	sentinel.failureCount = 2
	sentinel.backoffIdx = 2

	eng.mu.Lock()
	eng.sentinel = sentinel
	eng.mu.Unlock()

	eng.onNetworkChange("10.0.0.1", "eth0")

	if sentinel.failureCount != 0 {
		t.Fatalf("expected failureCount reset to 0 after onNetworkChange, got %d", sentinel.failureCount)
	}
	if sentinel.backoffIdx != 0 {
		t.Fatalf("expected backoffIdx reset to 0 after onNetworkChange, got %d", sentinel.backoffIdx)
	}

	select {
	case <-sentinel.wakeupCh:
		// OK
	default:
		t.Fatalf("expected wakeupCh signal after onNetworkChange")
	}
}

// 验收项 7：多用户并行高并发健康检测与 Failover 交叉验证
func TestMultiUserParallelSentinelFailover(t *testing.T) {
	const userCount = 10
	var wg sync.WaitGroup

	for i := 0; i < userCount; i++ {
		wg.Add(1)
		go func(uid int) {
			defer wg.Done()
			eng := NewEngine()
			sentinel := newNodeSentinel(eng)

			sub := &Subscription{
				Version: "2.0",
				Servers: []ServerConfig{
					{Name: "Node-Primary", Address: fmt.Sprintf("192.0.2.%d:443", uid*10+1), SNI: "node1.example.com", Token: fmt.Sprintf("tok-%d", uid)},
					{Name: "Node-Backup", Address: fmt.Sprintf("192.0.2.%d:443", uid*10+2), SNI: "node2.example.com", Token: fmt.Sprintf("tok-%d", uid)},
				},
			}
			applied, err := ApplySubscription(sub)
			if err != nil {
				t.Errorf("user %d ApplySubscription failed: %v", uid, err)
				return
			}
			eng.mu.Lock()
			eng.appliedSub = applied
			eng.activeAddr = sub.Servers[0].Address
			eng.activeToken = sub.Servers[0].Token
			eng.activeSNI = sub.Servers[0].SNI
			eng.sentinel = sentinel
			eng.mu.Unlock()

			// 模拟多用户并发主动探活与故障转移
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			sentinel.dialFn = func(pCtx context.Context, cfg *TransportConfig) (*Client, error) {
				if cfg.Address == sub.Servers[0].Address {
					return nil, errors.New("primary down")
				}
				return &Client{}, nil
			}

			// 触发 3 次失败判定并切换
			for round := 0; round < 3; round++ {
				sentinel.check(ctx)
			}

			eng.mu.RLock()
			finalAddr := eng.activeAddr
			eng.mu.RUnlock()

			if finalAddr != sub.Servers[1].Address {
				t.Errorf("user %d expected switch to backup %s, got %s", uid, sub.Servers[1].Address, finalAddr)
			}

			// 并发唤醒与网络变化测试
			eng.onNetworkChange("10.0.0.1", "eth0")
		}(i)
	}

	wg.Wait()
}
