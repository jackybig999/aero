// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package ios 提供 iOS AERO Lite 版本的框架接口。
//
// iOS 平台特殊要求：
//   - 使用 Apple NetworkExtension 框架（NEPacketTunnelProvider）
//   - 遵守 App Store 审核规则（不能有本地 SOCKS5 代理）
//   - 严格的内存管理与保活控制
//   - 核心数据面与分流逻辑统一复用 internal/clienttunnel (gVisor + AERO)
package ios

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/aero-protocol/aero-ech/internal/clienttunnel"
)

// PacketTunnel iOS Packet Tunnel Provider 接口
type PacketTunnel interface {
	StartTunnel(options map[string]interface{}) error
	StopTunnel(reason string) error
	HandlePackets(packets [][]byte) error
	UpdateRules(rulesJSON []byte) error
}

// TunnelConfig 隧道配置，与全平台统一
type TunnelConfig = clienttunnel.Config

// DefaultConfig 默认 iOS 配置
func DefaultConfig() TunnelConfig {
	return clienttunnel.DefaultConfig()
}

// PacketOutputCallback 定义 gVisor 产出数据包写回系统的回调函数
type PacketOutputCallback func(pkt []byte)

// AeroTunnel iOS AERO 隧道实现
type AeroTunnel struct {
	cfg       TunnelConfig
	engine    *clienttunnel.Engine
	onOut     PacketOutputCallback
	mu        sync.Mutex
	isRunning atomic.Bool
	cancel    context.CancelFunc
}

// NewAeroTunnel 创建 iOS 隧道实例
func NewAeroTunnel(cfg TunnelConfig) *AeroTunnel {
	return &AeroTunnel{
		cfg: cfg,
	}
}

// SetPacketCallback 注册向 iOS 系统写回数据包的回调
func (t *AeroTunnel) SetPacketCallback(cb PacketOutputCallback) {
	t.mu.Lock()
	t.onOut = cb
	t.mu.Unlock()
}

// StartTunnel 启动隧道
func (t *AeroTunnel) StartTunnel(options map[string]interface{}) error {
	if t.isRunning.Swap(true) {
		return fmt.Errorf("tunnel already running")
	}

	// 允许 options 覆盖配置
	if options != nil {
		if addr, ok := options["serverAddress"].(string); ok && addr != "" {
			t.cfg.ServerAddress = addr
		}
		if tok, ok := options["token"].(string); ok && tok != "" {
			t.cfg.Token = tok
		}
		if sub, ok := options["subscriptionUrl"].(string); ok && sub != "" {
			t.cfg.SubscriptionURL = sub
		}
	}

	eng, err := clienttunnel.NewEngine(t.cfg)
	if err != nil {
		t.isRunning.Store(false)
		return fmt.Errorf("init clienttunnel engine: %w", err)
	}

	outCallback := func(pkt []byte) {
		t.mu.Lock()
		cb := t.onOut
		t.mu.Unlock()
		if cb != nil {
			cb(pkt)
		}
	}

	if err := eng.StartPacketTunnel(outCallback); err != nil {
		t.isRunning.Store(false)
		return fmt.Errorf("start packet tunnel: %w", err)
	}

	t.mu.Lock()
	t.engine = eng
	t.mu.Unlock()

	return nil
}

// StopTunnel 停止隧道
func (t *AeroTunnel) StopTunnel(reason string) error {
	if !t.isRunning.Swap(false) {
		return nil
	}

	t.mu.Lock()
	eng := t.engine
	t.engine = nil
	t.mu.Unlock()

	if eng != nil {
		eng.Stop()
	}

	return nil
}

// HandlePackets 接收系统转发的 IP 包列表
func (t *AeroTunnel) HandlePackets(packets [][]byte) error {
	if !t.isRunning.Load() {
		return fmt.Errorf("tunnel not running")
	}

	t.mu.Lock()
	eng := t.engine
	t.mu.Unlock()

	if eng == nil {
		return fmt.Errorf("engine not initialized")
	}

	for _, pkt := range packets {
		if len(pkt) == 0 {
			continue
		}
		if err := eng.HandlePacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

// UpdateRules 动态更新分流规则
func (t *AeroTunnel) UpdateRules(rulesJSON []byte) error {
	t.mu.Lock()
	eng := t.engine
	t.mu.Unlock()

	if eng == nil {
		return fmt.Errorf("engine not running")
	}
	return eng.UpdateRules(rulesJSON)
}

// IsRunning 检查隧道是否运行中
func (t *AeroTunnel) IsRunning() bool {
	return t.isRunning.Load()
}

// Stats 返回隧道统计
func (t *AeroTunnel) Stats() clienttunnel.Stats {
	t.mu.Lock()
	eng := t.engine
	t.mu.Unlock()

	if eng == nil {
		return clienttunnel.Stats{IsRunning: false}
	}
	return eng.Stats()
}

// MemoryManager iOS 内存管理
type MemoryManager struct {
	maxCacheSize int
	maxQueueLen  int
}

// NewMemoryManager 创建内存管理器
func NewMemoryManager() *MemoryManager {
	return &MemoryManager{
		maxCacheSize: 1024 * 1024, // 1MB 缓存上限
		maxQueueLen:  256,         // 包队列上限
	}
}

// ShouldFlush 检查是否需要刷新缓存（内存压力时）
func (m *MemoryManager) ShouldFlush(currentUsage int64) bool {
	return currentUsage > int64(m.maxCacheSize)
}

// MemoryWarning 处理内存警告
func (m *MemoryManager) MemoryWarning() {}
