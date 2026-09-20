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
	"sync/atomic"
	"time"
)

// MigrationReason 会话迁移法定触发原因 (Rule L7)
type MigrationReason int

const (
	MigrationReasonUnknown MigrationReason = iota
	// MigrationReasonConsecutiveFailures ① 网络写连续失败 3 次
	MigrationReasonConsecutiveFailures
	// MigrationReasonVPSDown ② VPS 物理宕机 (HealthScore == 0)
	MigrationReasonVPSDown
	// MigrationReasonRiskReported ③ 客户端上报风控感知 (report-risk / dirty_ip_degraded)，必须在会话请求空闲期执行
	MigrationReasonRiskReported
)

func (r MigrationReason) String() string {
	switch r {
	case MigrationReasonConsecutiveFailures:
		return "write_failure_3x"
	case MigrationReasonVPSDown:
		return "vps_down_health_zero"
	case MigrationReasonRiskReported:
		return "risk_reported_idle"
	default:
		return "unknown"
	}
}

// ManagedConn 纳管的边缘节点底层网络连接
type ManagedConn struct {
	Raw      net.Conn
	Address  string
	LastUsed time.Time
	Active   bool
}

// StickyPool 粘性连接池：纳管单节点连接生命周期，杜绝随意漂移出口 IP (Rule L5, L7)
type StickyPool struct {
	mu                  sync.RWMutex
	ctx                 context.Context
	cancel              context.CancelFunc
	activeNode          string
	conns               map[string][]*ManagedConn
	consecutiveFailures atomic.Int32
	healthScore         atomic.Int32
	riskReported        atomic.Bool
	inflightRequests    atomic.Int32
	ttl                 time.Duration
	onMigration         func(oldNode, newNode string, reason MigrationReason)
}

// NewStickyPool 创建受 context 纳管的粘性连接池 (Rule L2, L5)
func NewStickyPool(ctx context.Context, defaultNode string, idleTTL time.Duration) *StickyPool {
	if idleTTL <= 0 {
		idleTTL = 10 * time.Minute // 铁律 L5：10 分钟 TTL 强制驱逐
	}
	subCtx, cancel := context.WithCancel(ctx)
	p := &StickyPool{
		ctx:        subCtx,
		cancel:     cancel,
		activeNode: defaultNode,
		conns:      make(map[string][]*ManagedConn),
		ttl:        idleTTL,
	}
	p.healthScore.Store(100) // 初始健康分 100

	// 铁律 L5 & L2：后台时钟巡检，10 分钟空闲连接强制驱逐，严格受 ctx 纳管
	go p.evictionLoop(subCtx)

	return p
}

func (p *StickyPool) evictionLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.CloseAll()
			return
		case <-ticker.C:
			p.EvictIdleConns()
		}
	}
}

// EvictIdleConns 强制回收超过 TTL 的空闲连接 (Rule L5)
func (p *StickyPool) EvictIdleConns() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	evicted := 0

	for node, list := range p.conns {
		var active []*ManagedConn
		for _, c := range list {
			if c == nil {
				continue
			}
			if now.Sub(c.LastUsed) > p.ttl {
				if c.Raw != nil {
					_ = c.Raw.Close()
				}
				evicted++
			} else {
				active = append(active, c)
			}
		}
		if len(active) == 0 {
			delete(p.conns, node)
		} else {
			p.conns[node] = active
		}
	}
	return evicted
}

// ActiveNode 获取当前粘滞的节点标识
func (p *StickyPool) ActiveNode() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.activeNode
}

// SetOnMigration 设置迁移回调
func (p *StickyPool) SetOnMigration(fn func(oldNode, newNode string, reason MigrationReason)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onMigration = fn
}

// AcquireRequest 标记请求开始借用连接
func (p *StickyPool) AcquireRequest() {
	p.inflightRequests.Add(1)
}

// ReleaseRequest 标记请求结束归还连接；若有延迟的风控迁移则在空闲时触发 (Rule L7)
func (p *StickyPool) ReleaseRequest(newNodeCandidate string) {
	remaining := p.inflightRequests.Add(-1)
	if remaining == 0 && p.riskReported.Load() && newNodeCandidate != "" {
		_ = p.TriggerMigration(newNodeCandidate, MigrationReasonRiskReported)
	}
}

// RecordWriteFailure 记录网络写失败；连续 3 次失败触发法定迁移 (Rule L7)
func (p *StickyPool) RecordWriteFailure(failoverNode string) bool {
	fails := p.consecutiveFailures.Add(1)
	if fails >= 3 && failoverNode != "" {
		err := p.TriggerMigration(failoverNode, MigrationReasonConsecutiveFailures)
		return err == nil
	}
	return false
}

// RecordWriteSuccess 重置写失败计数
func (p *StickyPool) RecordWriteSuccess() {
	p.consecutiveFailures.Store(0)
}

// UpdateHealthScore 更新节点健康分；HealthScore == 0 时触发物理宕机迁移 (Rule L7)
func (p *StickyPool) UpdateHealthScore(score int32, failoverNode string) bool {
	p.healthScore.Store(score)
	if score == 0 && failoverNode != "" {
		err := p.TriggerMigration(failoverNode, MigrationReasonVPSDown)
		return err == nil
	}
	return false
}

// ReportRiskPerception 上报风控感知（如接收到 dirty_ip_degraded 信号或 403 挑战）
func (p *StickyPool) ReportRiskPerception(failoverNode string) (migratedNow bool) {
	p.riskReported.Store(true)
	// 法定条件 ③：必须在请求空闲期 (inflight == 0) 执行
	if p.inflightRequests.Load() == 0 && failoverNode != "" {
		err := p.TriggerMigration(failoverNode, MigrationReasonRiskReported)
		return err == nil
	}
	return false
}

// CanMigrate 严格校验是否满足三大法定迁移条件 (Rule L7)
func (p *StickyPool) CanMigrate(reason MigrationReason) (bool, error) {
	switch reason {
	case MigrationReasonConsecutiveFailures:
		if p.consecutiveFailures.Load() < 3 {
			return false, fmt.Errorf("非法迁移拒绝：网络写失败仅 %d 次（法定要求连续 ≥ 3 次）", p.consecutiveFailures.Load())
		}
		return true, nil
	case MigrationReasonVPSDown:
		if p.healthScore.Load() > 0 {
			return false, fmt.Errorf("非法迁移拒绝：VPS 仍存活（HealthScore=%d，法定要求物理宕机 0）", p.healthScore.Load())
		}
		return true, nil
	case MigrationReasonRiskReported:
		if !p.riskReported.Load() {
			return false, errors.New("非法迁移拒绝：未收到客户端上报的风控感知信号")
		}
		if p.inflightRequests.Load() > 0 {
			return false, fmt.Errorf("非法迁移拒绝：当前仍有 %d 个活跃请求在途，必须等待空闲期", p.inflightRequests.Load())
		}
		return true, nil
	default:
		return false, errors.New("非法迁移拒绝：禁止无正当法定理由随意漂移出口 IP (Rule L7)")
	}
}

// TriggerMigration 执行 GoAway 会话迁移
func (p *StickyPool) TriggerMigration(newNode string, reason MigrationReason) error {
	if ok, err := p.CanMigrate(reason); !ok {
		return err
	}

	p.mu.Lock()
	oldNode := p.activeNode
	if oldNode == newNode {
		p.mu.Unlock()
		return nil
	}
	p.activeNode = newNode

	// 优雅关闭老节点连接
	if oldList, ok := p.conns[oldNode]; ok {
		for _, c := range oldList {
			if c != nil && c.Raw != nil {
				_ = c.Raw.Close()
			}
		}
		delete(p.conns, oldNode)
	}

	// 重置守卫状态
	p.consecutiveFailures.Store(0)
	p.riskReported.Store(false)
	callback := p.onMigration
	p.mu.Unlock()

	if callback != nil {
		callback(oldNode, newNode, reason)
	}
	return nil
}

// CloseAll 关闭连接池内所有连接并终止生命周期
func (p *StickyPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for node, list := range p.conns {
		for _, c := range list {
			if c != nil && c.Raw != nil {
				_ = c.Raw.Close()
			}
		}
		delete(p.conns, node)
	}
	if p.cancel != nil {
		p.cancel()
	}
}
