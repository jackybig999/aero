// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// MigrationState QUIC 连接漫游状态机枚举
type MigrationState int32

const (
	// MigrationStateIdle 空闲状态，当前路径稳定运行
	MigrationStateIdle MigrationState = iota
	// MigrationStateProbing 探针探测中，正向新物理网络通道发送 Path Challenge
	MigrationStateProbing
	// MigrationStateSwitched 漫游成功，已无缝切换为主力数据传输路径
	MigrationStateSwitched
	// MigrationStateFailed 探针超时或失败，已安全回退到原有路径
	MigrationStateFailed
	// MigrationStateRedialing 原连接已断死且探针失败，需触发重拨降级
	MigrationStateRedialing
)

func (s MigrationState) String() string {
	switch s {
	case MigrationStateIdle:
		return "Idle"
	case MigrationStateProbing:
		return "Probing"
	case MigrationStateSwitched:
		return "Switched"
	case MigrationStateFailed:
		return "Failed"
	case MigrationStateRedialing:
		return "Redialing"
	default:
		return fmt.Sprintf("MigrationState(%d)", int32(s))
	}
}

var (
	// ErrMigrationThrottled 在 150ms 防抖节流窗口内被拦截
	ErrMigrationThrottled = errors.New("quic migration throttled: within debounce window")
	// ErrMigrationInProgress 已有漫游迁移流程正在执行中
	ErrMigrationInProgress = errors.New("quic migration already in progress")
	// ErrNilConnection 未提供有效的 QUIC 连接
	ErrNilConnection = errors.New("quic migration: connection is nil")
	// ErrNeedRedial 原路径已断死且新路径探测失败，需触发全新重拨降级
	ErrNeedRedial = errors.New("quic migration failed: parent connection dead, need redial")
	// ErrNilPathController 新路径控制器创建失败或为空
	ErrNilPathController = errors.New("quic migration: new path controller is nil")
)

// PathController 抽象 QUIC Path 接口，对齐 quic-go (*quic.Path) 行为
type PathController interface {
	Probe(ctx context.Context) error
	Switch() error
	Close() error
}

// MigrationConfig 漫游迁移参数配置
type MigrationConfig struct {
	// DebounceWindow 物理网卡事件防抖节流窗口（默认 150ms）
	DebounceWindow time.Duration
	// ProbeTimeout 探针超时时间（默认 600ms）
	ProbeTimeout time.Duration
	// DrainBaseGrace 安全排空基础延时（默认 300ms，排空总耗时为 2*RTT + DrainBaseGrace）
	DrainBaseGrace time.Duration
	// DefaultFallbackRTT 当连接未采样到有效 SmoothedRTT 时使用的备选 RTT（默认 50ms）
	DefaultFallbackRTT time.Duration
}

// DefaultMigrationConfig 返回 AERO-V2 规范默认迁移配置
func DefaultMigrationConfig() MigrationConfig {
	return MigrationConfig{
		DebounceWindow:     150 * time.Millisecond,
		ProbeTimeout:       600 * time.Millisecond,
		DrainBaseGrace:     300 * time.Millisecond,
		DefaultFallbackRTT: 50 * time.Millisecond,
	}
}

// QUICMigrator 管理单个 QUIC 连接的生命周期漫游状态机与物理套接字安全排空流水线
type QUICMigrator struct {
	cfg MigrationConfig
	mu  sync.Mutex

	state             atomic.Int32
	lastMigrationNano atomic.Int64
	activePath        PathController

	// 监控统计指标
	totalAttempts  atomic.Int64
	successCount   atomic.Int64
	failedCount    atomic.Int64
	redialCount    atomic.Int64
	throttledCount atomic.Int64

	// drainWG 用于测试时平稳等待排空协程
	drainWG sync.WaitGroup
}

// NewQUICMigrator 创建漫游状态机管理器
func NewQUICMigrator(cfg *MigrationConfig) *QUICMigrator {
	c := DefaultMigrationConfig()
	if cfg != nil {
		if cfg.DebounceWindow > 0 {
			c.DebounceWindow = cfg.DebounceWindow
		}
		if cfg.ProbeTimeout > 0 {
			c.ProbeTimeout = cfg.ProbeTimeout
		}
		if cfg.DrainBaseGrace > 0 {
			c.DrainBaseGrace = cfg.DrainBaseGrace
		}
		if cfg.DefaultFallbackRTT > 0 {
			c.DefaultFallbackRTT = cfg.DefaultFallbackRTT
		}
	}
	m := &QUICMigrator{
		cfg: c,
	}
	m.state.Store(int32(MigrationStateIdle))
	return m
}

// State 返回当前漫游状态机状态
func (m *QUICMigrator) State() MigrationState {
	return MigrationState(m.state.Load())
}

// Stats 返回状态机统计指标 (attempts, successes, failures, redials, throttled)
func (m *QUICMigrator) Stats() (attempts, successes, failures, redials, throttled int64) {
	return m.totalAttempts.Load(), m.successCount.Load(), m.failedCount.Load(), m.redialCount.Load(), m.throttledCount.Load()
}

// SetActivePath 设置当前主力路径控制器
func (m *QUICMigrator) SetActivePath(p PathController) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activePath = p
}

// ActivePath 获取当前主力路径控制器
func (m *QUICMigrator) ActivePath() PathController {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activePath
}

// DrainOptions 承载旧套接字安全排空所需的资源
type DrainOptions struct {
	OldPath       PathController
	OldTransport  io.Closer
	OldPacketConn io.Closer
	SmoothedRTT   time.Duration
}

// MigrateWithController 基于已初始化的 PathController 执行状态机流转与切换
// 适用于 quic-go 原生 conn.AddPath 产出的 path 或 mock 测试
func (m *QUICMigrator) MigrateWithController(
	ctx context.Context,
	newPath PathController,
	drainOpts DrainOptions,
	parentConnAlive func() bool,
) error {
	m.totalAttempts.Add(1)

	// 1. 防抖检查 (Debounce window: 150ms)
	now := time.Now().UnixNano()
	last := m.lastMigrationNano.Load()
	if last > 0 && time.Duration(now-last) < m.cfg.DebounceWindow {
		m.throttledCount.Add(1)
		return ErrMigrationThrottled
	}
	if !m.lastMigrationNano.CompareAndSwap(last, now) {
		m.throttledCount.Add(1)
		return ErrMigrationThrottled
	}

	// 2. 状态互斥排队
	m.mu.Lock()
	currentState := MigrationState(m.state.Load())
	if currentState == MigrationStateProbing {
		m.mu.Unlock()
		m.throttledCount.Add(1)
		return ErrMigrationInProgress
	}
	if newPath == nil {
		m.mu.Unlock()
		m.failedCount.Add(1)
		return ErrNilPathController
	}
	m.state.Store(int32(MigrationStateProbing))
	m.mu.Unlock()

	// 3. 执行探针探测 (Probe with timeout, 默认 600ms)
	probeCtx, cancel := context.WithTimeout(ctx, m.cfg.ProbeTimeout)
	defer cancel()

	probeErr := newPath.Probe(probeCtx)
	if probeErr != nil {
		// 探测失败，清理新路径资源
		_ = newPath.Close()
		if drainOpts.OldPacketConn != nil {
			// 新创建的资源若失败应在此处清理；此处若外部传有对应资源也可处理
		}

		m.mu.Lock()
		defer m.mu.Unlock()
		m.failedCount.Add(1)

		// 检查原连接是否健康；若已断死，则触发重拨降级
		if parentConnAlive != nil && !parentConnAlive() {
			m.state.Store(int32(MigrationStateRedialing))
			m.redialCount.Add(1)
			return fmt.Errorf("%w: probe failed (%v)", ErrNeedRedial, probeErr)
		}

		m.state.Store(int32(MigrationStateFailed))
		return fmt.Errorf("path probe failed: %w", probeErr)
	}

	// 4. 探针成功，执行无缝切换 (Switch)
	switchErr := newPath.Switch()
	if switchErr != nil {
		_ = newPath.Close()

		m.mu.Lock()
		defer m.mu.Unlock()
		m.failedCount.Add(1)

		if parentConnAlive != nil && !parentConnAlive() {
			m.state.Store(int32(MigrationStateRedialing))
			m.redialCount.Add(1)
			return fmt.Errorf("%w: switch failed (%v)", ErrNeedRedial, switchErr)
		}

		m.state.Store(int32(MigrationStateFailed))
		return fmt.Errorf("path switch failed: %w", switchErr)
	}

	// 5. 切换成功，更新主力路径并置状态为 MigrationStateSwitched
	m.mu.Lock()
	m.activePath = newPath
	m.state.Store(int32(MigrationStateSwitched))
	m.successCount.Add(1)
	m.mu.Unlock()

	// 6. 安全平滑排空流水线 (2*RTT + 300ms)
	m.startGracefulDrain(ctx, drainOpts)

	return nil
}

// startGracefulDrain 启动旧套接字延迟排空流水线：
// 先关闭旧 Path，保持底层旧 UDP 套接字存活 2*RTT + 300ms 排空在途数据包，然后销毁物理套接字
func (m *QUICMigrator) startGracefulDrain(ctx context.Context, opts DrainOptions) {
	// 立即关闭逻辑路径（防止新数据继续写入旧通道）
	if opts.OldPath != nil {
		_ = opts.OldPath.Close()
	}

	// 计算安全排空时间
	rtt := opts.SmoothedRTT
	if rtt <= 0 {
		rtt = m.cfg.DefaultFallbackRTT
	}
	drainDelay := 2*rtt + m.cfg.DrainBaseGrace

	m.drainWG.Add(1)
	go func(delay time.Duration, tr, pconn io.Closer) {
		defer m.drainWG.Done()

		// 延迟等待，允许飞行中的响应数据包被完全接收排空
		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-timer.C:
		case <-ctx.Done():
		}

		// 排空期满后，安全关闭旧物理套接字与传输层
		if pconn != nil {
			_ = pconn.Close()
		}
		if tr != nil {
			_ = tr.Close()
		}
	}(drainDelay, opts.OldTransport, opts.OldPacketConn)
}

// MigrateQUICConn 针对真实 quic.Conn 执行官方 Connection Migration 漫游切换
func (m *QUICMigrator) MigrateQUICConn(
	ctx context.Context,
	conn *quic.Conn,
	newTransport *quic.Transport,
	oldDrain DrainOptions,
) error {
	if conn == nil {
		return ErrNilConnection
	}
	if newTransport == nil {
		return errors.New("new quic transport cannot be nil")
	}

	// 调用 quic-go 官方原生 Conn.AddPath 挂载新物理传输通道
	newPath, err := conn.AddPath(newTransport)
	if err != nil {
		m.failedCount.Add(1)
		return fmt.Errorf("quic conn add path: %w", err)
	}

	// 提取原连接当前 RTT 指标
	stats := conn.ConnectionStats()
	rtt := stats.SmoothedRTT
	if rtt <= 0 {
		rtt = stats.LatestRTT
	}
	oldDrain.SmoothedRTT = rtt

	parentAlive := func() bool {
		return conn.Context().Err() == nil
	}

	return m.MigrateWithController(ctx, newPath, oldDrain, parentAlive)
}
