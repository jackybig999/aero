// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var backoffDurations = []time.Duration{
	10 * time.Second,
	30 * time.Second,
	60 * time.Second,
	120 * time.Second,
}

// nodeSentinel 节点健康哨兵，负责定期探活及故障自动转移
type nodeSentinel struct {
	engine           *Engine
	wakeupCh         chan struct{}
	failureCount     int
	backoffIdx       int
	mu               sync.Mutex
	dialFn           func(ctx context.Context, cfg *TransportConfig) (*Client, error)
	checkInterval    time.Duration
	backoffDurations []time.Duration
	lastRTT          atomic.Int64
}

// LastRTT 获取最近一次探活 RTT
func (s *nodeSentinel) LastRTT() time.Duration {
	return time.Duration(s.lastRTT.Load())
}

// newNodeSentinel 创建节点健康哨兵
func newNodeSentinel(e *Engine) *nodeSentinel {
	return &nodeSentinel{
		engine:           e,
		wakeupCh:         make(chan struct{}, 1),
		checkInterval:    10 * time.Second,
		backoffDurations: backoffDurations,
		dialFn:           Dial,
	}
}

// wakeup 重置退避并唤醒探活循环
func (s *nodeSentinel) wakeup() {
	s.mu.Lock()
	s.failureCount = 0
	s.backoffIdx = 0
	s.mu.Unlock()

	select {
	case s.wakeupCh <- struct{}{}:
	default:
	}
}

// run 哨兵后台主循环
func (s *nodeSentinel) run(ctx context.Context) {
	interval := s.checkInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wakeupCh:
			s.mu.Lock()
			s.failureCount = 0
			s.backoffIdx = 0
			s.mu.Unlock()
			ticker.Reset(interval)
		case <-ticker.C:
		}

		if !s.check(ctx) {
			return
		}

		s.mu.Lock()
		nextDuration := interval
		if s.backoffIdx > 0 {
			durations := s.backoffDurations
			if len(durations) == 0 {
				durations = backoffDurations
			}
			idx := s.backoffIdx
			if idx >= len(durations) {
				idx = len(durations) - 1
			}
			nextDuration = durations[idx]
		}
		s.mu.Unlock()
		ticker.Reset(nextDuration)
	}
}

func (s *nodeSentinel) check(ctx context.Context) bool {
	if s.isCurrentNodeHealthy(ctx) {
		s.mu.Lock()
		s.failureCount = 0
		s.backoffIdx = 0
		s.mu.Unlock()
		return true
	}

	s.mu.Lock()
	s.failureCount++
	count := s.failureCount
	s.mu.Unlock()

	log.Printf("[SENTINEL] Current node health check failed (%d/3)", count)

	if count >= 3 {
		if !s.failover(ctx) {
			log.Printf("[SENTINEL] all candidate nodes failed, stopping data plane")
			_ = s.engine.Stop()
			return false
		}
	}
	return true
}

// isPassiveHealthy 检查当前连接是否被动健康（连接正常且最后活跃在 15s 内）
func isPassiveHealthy(addr string, pool ISessionPool) bool {
	if addr == "" || pool == nil {
		return false
	}
	if checker, ok := pool.(interface{ IsPassiveHealthy(addr string) bool }); ok {
		return checker.IsPassiveHealthy(addr)
	}
	sp, ok := pool.(*SessionPool)
	if !ok || sp == nil {
		return false
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()

	client, ok := sp.clients[addr]
	if !ok || client == nil {
		return false
	}
	if client.conn != nil && client.conn.Context().Err() != nil {
		return false
	}
	last := client.lastActive.Load()
	if last <= 0 {
		return false
	}
	return time.Since(time.UnixMilli(last)) <= 15*time.Second
}

// isCurrentNodeHealthy 判定当前节点健康状态：先被动感知，未命中则发起独立轻量 Dial 探活
func (s *nodeSentinel) isCurrentNodeHealthy(ctx context.Context) bool {
	s.engine.mu.RLock()
	addr := s.engine.activeAddr
	sni := s.engine.activeSNI
	pool := s.engine.sessionPool
	s.engine.mu.RUnlock()

	if addr == "" {
		return false
	}

	// 1. 被动感知：检查最后活跃时间在 15s 内且连接正常
	if isPassiveHealthy(addr, pool) {
		return true
	}

	// 2. 主动探活：未命中则使用 DefaultTransportConfig 发起独立轻量 Dial
	_, _, _, ip := getActiveEdge()
	cfg := DefaultTransportConfig(addr, sni)
	if ip != nil {
		port := 443
		if _, portStr, err := net.SplitHostPort(addr); err == nil {
			if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
				port = p
			}
		}
		cfg.RemoteUDPAddr = &net.UDPAddr{IP: ip, Port: port}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	dial := s.dialFn
	if dial == nil {
		dial = Dial
	}

	start := time.Now()
	client, err := dial(probeCtx, cfg)
	if err != nil {
		return false
	}
	s.lastRTT.Store(time.Since(start).Nanoseconds())
	// 成功即 Close()，严禁入池
	_ = client.Close()
	return true
}

// failover 触发故障转移：浅拷贝 servers 快照并立即释放读锁，无锁探测各候选节点
func (s *nodeSentinel) failover(ctx context.Context) bool {
	s.engine.mu.RLock()
	currentAddr := s.engine.activeAddr
	var servers []ServerConfig
	if s.engine.appliedSub != nil {
		servers = append(servers, s.engine.appliedSub.Servers...)
	}
	s.engine.mu.RUnlock()

	if len(servers) == 0 {
		s.enterBackoff()
		return false
	}

	dial := s.dialFn
	if dial == nil {
		dial = Dial
	}

	// 无锁探测各候选节点
	for _, srv := range servers {
		if srv.Address == "" || srv.Address == currentAddr {
			continue
		}

		if ctx.Err() != nil {
			return false
		}

		candHost, candPortStr, err := net.SplitHostPort(srv.Address)
		if err != nil {
			candHost = srv.Address
			candPortStr = "443"
		}
		candPort := 443
		if p, perr := strconv.Atoi(candPortStr); perr == nil && p > 0 {
			candPort = p
		}

		candIP, rerr := resolvePhysicalIPv4(candHost)
		if rerr != nil || candIP == nil {
			continue
		}

		cfg := DefaultTransportConfig(srv.Address, srv.SNI)
		cfg.RemoteUDPAddr = &net.UDPAddr{IP: candIP, Port: candPort}

		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		client, err := dial(probeCtx, cfg)
		cancel()

		if err == nil && client != nil {
			_ = client.Close()
			// 首个可达节点调用 e.SwitchActiveNode(srv.Address)
			if switchErr := s.engine.SwitchActiveNode(srv.Address); switchErr == nil {
				s.mu.Lock()
				s.failureCount = 0
				s.backoffIdx = 0
				s.mu.Unlock()
				log.Printf("[SENTINEL] failover: successfully switched from %s to %s", currentAddr, srv.Address)
				return true
			}
		}
	}

	s.enterBackoff()
	return false
}

func (s *nodeSentinel) enterBackoff() {
	s.mu.Lock()
	durations := s.backoffDurations
	if len(durations) == 0 {
		durations = backoffDurations
	}
	if s.backoffIdx < len(durations)-1 {
		s.backoffIdx++
	}
	curIdx := s.backoffIdx
	curDuration := durations[curIdx]
	s.mu.Unlock()

	log.Printf("[SENTINEL] failover: all candidates unreachable, entering backoff level %d (%v)", curIdx, curDuration)
}
