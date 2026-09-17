// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package edgepool 实现节点调度、路径质量探测与无感平滑切换。
package edgepool

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SwitchPath 传输路径
type SwitchPath struct {
	ID       string
	Protocol string // "tcp", "quic"
	Address  string
	RTT      time.Duration
	LossRate float64
	Active   bool
}

// ConnWrapper 包装 net.Conn，提供统计功能
type ConnWrapper struct {
	net.Conn
	bytesRead    atomic.Uint64
	bytesWritten atomic.Uint64
	rttSamples   []time.Duration
	rttMu        sync.RWMutex
	lastActivity time.Time
	actMu        sync.RWMutex
}

// NewConnWrapper 创建带统计的连接包装器
func NewConnWrapper(conn net.Conn) *ConnWrapper {
	return &ConnWrapper{
		Conn:         conn,
		lastActivity: time.Now(),
	}
}

func (c *ConnWrapper) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.bytesRead.Add(uint64(n))
		c.actMu.Lock()
		c.lastActivity = time.Now()
		c.actMu.Unlock()
	}
	return n, err
}

func (c *ConnWrapper) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.bytesWritten.Add(uint64(n))
		c.actMu.Lock()
		c.lastActivity = time.Now()
		c.actMu.Unlock()
	}
	return n, err
}

// RecordRTT 记录一次 RTT 采样（保留最近 10 次）
func (c *ConnWrapper) RecordRTT(rtt time.Duration) {
	c.rttMu.Lock()
	defer c.rttMu.Unlock()
	c.rttSamples = append(c.rttSamples, rtt)
	if len(c.rttSamples) > 10 {
		c.rttSamples = c.rttSamples[1:]
	}
}

// AvgRTT 计算平均 RTT
func (c *ConnWrapper) AvgRTT() time.Duration {
	c.rttMu.RLock()
	defer c.rttMu.RUnlock()
	if len(c.rttSamples) == 0 {
		return 0
	}
	var sum time.Duration
	for _, r := range c.rttSamples {
		sum += r
	}
	return sum / time.Duration(len(c.rttSamples))
}

// Stats 返回连接统计
func (c *ConnWrapper) Stats() (read uint64, written uint64, avgRTT time.Duration) {
	return c.bytesRead.Load(), c.bytesWritten.Load(), c.AvgRTT()
}

// SwitchConfig 切换引擎配置
type SwitchConfig struct {
	SwitchThreshold float64       // RTT 突增阈值（如 1.5 表示增长 50% 时切换）
	LossThreshold   float64       // 丢包率阈值（如 0.05 表示丢包 >5% 切换）
	ProbeInterval   time.Duration // 质量检测间隔
	SwitchCooldown  time.Duration // 切换冷却时间（防震荡）
	PrewarmEnabled  bool          // 是否开启备用连接预热
}

// DefaultSwitchConfig 返回默认配置
func DefaultSwitchConfig() SwitchConfig {
	return SwitchConfig{
		SwitchThreshold: 1.5,
		LossThreshold:   0.05,
		ProbeInterval:   5 * time.Second,
		SwitchCooldown:  10 * time.Second,
		PrewarmEnabled:  true,
	}
}

// SwitchEngine 无感切换引擎
type SwitchEngine struct {
	primary         *ConnWrapper
	secondary       *ConnWrapper
	currentPathID   string
	paths           map[string]SwitchPath
	mu              sync.RWMutex
	switchThreshold float64
	lossThreshold   float64
	probeInterval   time.Duration
	switchCooldown  time.Duration
	lastSwitchTime  time.Time
	isSwitching     atomic.Bool
	seqSynced       atomic.Uint64
	onSwitch        func(oldPath, newPath string)
}

// NewSwitchEngine 创建切换引擎
func NewSwitchEngine(cfg SwitchConfig) *SwitchEngine {
	return &SwitchEngine{
		paths:           make(map[string]SwitchPath),
		switchThreshold: cfg.SwitchThreshold,
		lossThreshold:   cfg.LossThreshold,
		probeInterval:   cfg.ProbeInterval,
		switchCooldown:  cfg.SwitchCooldown,
	}
}

// SetPrimary 设置主连接
func (e *SwitchEngine) SetPrimary(conn net.Conn, path SwitchPath) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.primary = NewConnWrapper(conn)
	e.currentPathID = path.ID
	e.paths[path.ID] = path
}

// SetSecondary 设置备用连接
func (e *SwitchEngine) SetSecondary(conn net.Conn, path SwitchPath) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.secondary != nil {
		e.secondary.Close()
	}
	e.secondary = NewConnWrapper(conn)
	e.paths[path.ID] = path
}

// CurrentPath 返回当前路径
func (e *SwitchEngine) CurrentPath() SwitchPath {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if p, ok := e.paths[e.currentPathID]; ok {
		return p
	}
	return SwitchPath{ID: "", Protocol: "tcp"}
}

// ShouldSwitch 判断是否需要切换
func (e *SwitchEngine) ShouldSwitch() (string, bool) {
	if e.isSwitching.Load() {
		return "", false
	}

	if time.Since(e.lastSwitchTime) < e.switchCooldown {
		return "", false
	}

	e.mu.RLock()
	primary := e.primary
	paths := e.paths
	currentID := e.currentPathID
	e.mu.RUnlock()

	if primary == nil {
		return "", false
	}

	currentRTT := primary.AvgRTT()
	if currentRTT == 0 {
		return "", false
	}

	currentPath := paths[currentID]
	if currentPath.LossRate > e.lossThreshold {
		best := e.findBestPath()
		if best != "" && best != currentID {
			return best, true
		}
	}

	best := e.findBestPath()
	if best != "" && best != currentID {
		bestPath := paths[best]
		if bestPath.RTT > 0 && float64(currentRTT) > float64(bestPath.RTT)*e.switchThreshold {
			return best, true
		}
	}

	return "", false
}

func (e *SwitchEngine) findBestPath() string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var best string
	var bestRTT time.Duration = -1

	for id, path := range e.paths {
		if !path.Active {
			continue
		}
		if path.LossRate > e.lossThreshold {
			continue
		}
		if bestRTT < 0 || path.RTT < bestRTT {
			bestRTT = path.RTT
			best = id
		}
	}

	return best
}

// SwitchTo 执行切换到指定路径
func (e *SwitchEngine) SwitchTo(ctx context.Context, targetPathID string, dialFn func(SwitchPath) (net.Conn, error)) error {
	if !e.isSwitching.CompareAndSwap(false, true) {
		return fmt.Errorf("switching already in progress")
	}
	defer e.isSwitching.Store(false)

	e.mu.RLock()
	targetPath, ok := e.paths[targetPathID]
	oldConn := e.primary
	e.mu.RUnlock()

	if !ok {
		return fmt.Errorf("path %s not found", targetPathID)
	}

	var newConn net.Conn
	var err error

	e.mu.Lock()
	if e.secondary != nil && e.currentPathID == targetPathID {
		newConn = e.secondary.Conn
		e.secondary = nil
	}
	e.mu.Unlock()

	if newConn == nil {
		newConn, err = dialFn(targetPath)
		if err != nil {
			return fmt.Errorf("dial target path %s: %w", targetPathID, err)
		}
	}

	e.mu.Lock()
	e.primary = NewConnWrapper(newConn)
	e.currentPathID = targetPathID
	e.lastSwitchTime = time.Now()
	e.mu.Unlock()

	if oldConn != nil {
		go func(c net.Conn) {
			time.Sleep(3 * time.Second)
			c.Close()
		}(oldConn)
	}

	return nil
}

// ActiveConn 获取当前活跃的连接
func (e *SwitchEngine) ActiveConn() net.Conn {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.primary != nil {
		return e.primary
	}
	return nil
}

// UpdatePathQuality 更新某条路径的质量数据
func (e *SwitchEngine) UpdatePathQuality(pathID string, rtt time.Duration, lossRate float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, ok := e.paths[pathID]; ok {
		p.RTT = rtt
		p.LossRate = lossRate
		e.paths[pathID] = p
	}
}

// AddPath 添加或更新一条候选路径
func (e *SwitchEngine) AddPath(path SwitchPath) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.paths[path.ID] = path
}

// RemovePath 移除候选路径
func (e *SwitchEngine) RemovePath(pathID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.paths, pathID)
}

// Read 从当前活跃连接读
func (e *SwitchEngine) Read(p []byte) (int, error) {
	conn := e.ActiveConn()
	if conn == nil {
		return 0, io.EOF
	}
	return conn.Read(p)
}

// Write 向当前活跃连接写
func (e *SwitchEngine) Write(p []byte) (int, error) {
	conn := e.ActiveConn()
	if conn == nil {
		return 0, io.ErrClosedPipe
	}
	return conn.Write(p)
}

// Close 关闭所有连接
func (e *SwitchEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var errs []error
	if e.primary != nil {
		if err := e.primary.Close(); err != nil {
			errs = append(errs, err)
		}
		e.primary = nil
	}
	if e.secondary != nil {
		if err := e.secondary.Close(); err != nil {
			errs = append(errs, err)
		}
		e.secondary = nil
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// OnSwitch 设置切换回调
func (e *SwitchEngine) OnSwitch(fn func(oldPath, newPath string)) {
	e.mu.Lock()
	e.onSwitch = fn
	e.mu.Unlock()
}

// StartMonitor 启动后台监控和切换决策
func (e *SwitchEngine) StartMonitor(ctx context.Context) {
	ticker := time.NewTicker(e.probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, should := e.ShouldSwitch(); should {
				e.mu.RLock()
				currentID := e.currentPathID
				cb := e.onSwitch
				e.mu.RUnlock()
				if cb != nil {
					cb(currentID, "")
				}
			}
		}
	}
}
