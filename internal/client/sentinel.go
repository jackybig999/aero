// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

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

	// failoverMu 串行化故障转移：哨兵与重连协程（engine_reconnect.go）都会调用 failover，
	// 同时对同一活动节点做切换会互相覆盖。
	failoverMu sync.Mutex
	// unreachableMsg 是哨兵写入引擎 lastErr 的文案（受 mu 保护）；空表示哨兵没有设置错误。
	unreachableMsg string
}

// unreachableErrText 全部候选节点不可用时展示的错误；数据面保持，由重连协程负责恢复会话。
const unreachableErrText = "no reachable node: all candidates failed, retrying with backoff"

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

		nextDuration := s.nextInterval(interval)
		ticker.Reset(nextDuration)
	}
}

// nextInterval 返回下一次探活的间隔：没有退避时用 base，否则取 backoffDurations[backoffIdx]（封顶于最后一档）。
func (s *nodeSentinel) nextInterval(base time.Duration) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backoffIdx <= 0 {
		return base
	}
	durations := s.backoffDurations
	if len(durations) == 0 {
		durations = backoffDurations
	}
	idx := s.backoffIdx
	if idx >= len(durations) {
		idx = len(durations) - 1
	}
	return durations[idx]
}

// check 执行一轮健康检查。返回 false 仅表示 ctx 已取消（哨兵应退出）；
// 全部候选节点不可用时不停止引擎：数据面与 TUN 保持，记录可见错误并按 backoffDurations 退避后重试。
func (s *nodeSentinel) check(ctx context.Context) bool {
	if s.isCurrentNodeHealthy(ctx) {
		s.mu.Lock()
		s.failureCount = 0
		s.backoffIdx = 0
		s.mu.Unlock()
		s.clearUnreachable()
		return true
	}

	s.mu.Lock()
	s.failureCount++
	count := s.failureCount
	s.mu.Unlock()

	log.Printf("[SENTINEL] Current node health check failed (%d/3)", count)

	if count >= 3 {
		if s.failover(ctx) {
			s.clearUnreachable()
		} else {
			if ctx.Err() != nil {
				return false
			}
			log.Printf("[SENTINEL] all candidate nodes failed, keeping data plane and retrying with backoff")
			s.reportUnreachable(ctx)
		}
	}
	return ctx.Err() == nil
}

// reportUnreachable 把“无可用节点”写入引擎状态（UI 可见）；引擎未运行或已停止时不写，避免覆盖 Stop 清空的状态。
func (s *nodeSentinel) reportUnreachable(ctx context.Context) {
	e := s.engine
	if !e.running.Load() {
		return
	}
	e.SetLastError(unreachableErrText)
	s.mu.Lock()
	s.unreachableMsg = unreachableErrText
	s.mu.Unlock()
	// 与 stopLocked 竞争：若期间已停止，撤销刚写入的错误
	if ctx.Err() != nil || !e.running.Load() {
		s.clearUnreachable()
	}
}

// clearUnreachable 清除哨兵自己写入的错误；别处（如重连协程的 edge 拒绝）写入的错误不动。
func (s *nodeSentinel) clearUnreachable() {
	s.mu.Lock()
	msg := s.unreachableMsg
	s.unreachableMsg = ""
	s.mu.Unlock()
	if msg == "" {
		return
	}
	e := s.engine
	e.lastErrMu.Lock()
	if e.lastErr == msg && e.lastErrCode == "CONNECT_ERROR" {
		e.lastErr = ""
		e.lastErrCode = ""
	}
	e.lastErrMu.Unlock()
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
//
// 分工：哨兵只负责“选哪个节点”（探测并 SwitchActiveNode），重连协程只负责“在当前节点上恢复会话”；
// 两者都可能调用 failover，故用 failoverMu 串行化，且等锁期间若活动节点已被对方切走则直接返回，
// 不再二次切换。
func (s *nodeSentinel) failover(ctx context.Context) bool {
	s.engine.mu.RLock()
	entryAddr := s.engine.activeAddr
	s.engine.mu.RUnlock()

	s.failoverMu.Lock()
	defer s.failoverMu.Unlock()

	s.engine.mu.RLock()
	currentAddr := s.engine.activeAddr
	var servers []ServerConfig
	if s.engine.appliedSub != nil {
		servers = append(servers, s.engine.appliedSub.Servers...)
	}
	s.engine.mu.RUnlock()

	if currentAddr != entryAddr {
		// 等锁期间另一方已完成切换
		return true
	}

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
		if srv.Address == "" || srv.Address == currentAddr || s.engine.nodeUnavailable(srv.Address) {
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

		var candIP net.IP
		if srv.IP != "" {
			if parsed := net.ParseIP(srv.IP); parsed != nil {
				candIP = parsed.To4()
			}
		}
		if candIP == nil {
			candIP, _ = resolvePhysicalIPv4(candHost)
		}
		if candIP == nil {
			continue
		}

		cfg := DefaultTransportConfig(srv.Address, srv.SNI)
		cfg.RemoteUDPAddr = &net.UDPAddr{IP: candIP, Port: candPort}
		if len(srv.AltPorts) > 0 {
			cfg.AltPorts = srv.AltPorts
		}

		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		client, err := dial(probeCtx, cfg)
		cancel()

		if err == nil && client != nil {
			targetAddr := srv.Address
			if actualPort := client.ActualPort(); actualPort > 0 && actualPort != candPort {
				targetAddr = net.JoinHostPort(candHost, strconv.Itoa(actualPort))
				s.engine.mu.Lock()
				if s.engine.appliedSub != nil {
					if s.engine.appliedSub.IPs != nil {
						s.engine.appliedSub.IPs[targetAddr] = candIP.String()
					}
					if s.engine.appliedSub.Tokens != nil {
						s.engine.appliedSub.Tokens[targetAddr] = srv.Token
					}
					if s.engine.appliedSub.SNIs != nil {
						s.engine.appliedSub.SNIs[targetAddr] = srv.SNI
					}
					if s.engine.appliedSub.AltPorts != nil && len(srv.AltPorts) > 0 {
						s.engine.appliedSub.AltPorts[targetAddr] = srv.AltPorts
					}
					for i := range s.engine.appliedSub.Servers {
						if s.engine.appliedSub.Servers[i].Address == srv.Address {
							s.engine.appliedSub.Servers[i].Address = targetAddr
							break
						}
					}
				}
				s.engine.mu.Unlock()
			}
			_ = client.Close()
			// 首个可达节点调用 e.SwitchActiveNode(targetAddr)
			if switchErr := s.engine.SwitchActiveNode(targetAddr); switchErr == nil {
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
