// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package edgepool 实现网络劣化检测与双连接无感迁移。
package edgepool

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// Detector 劣化检测器
type Detector struct {
	mu            sync.Mutex
	rttSamples    []time.Duration
	lossCount     int
	totalCount    int
	maxSamples    int
	rttThreshold  float64 // RTT 突增阈值（倍数），默认 1.5
	lossThreshold float64 // 丢包率阈值，默认 0.05
}

// NewDetector 创建劣化检测器
func NewDetector(maxSamples int) *Detector {
	return &Detector{
		rttSamples:    make([]time.Duration, 0, maxSamples),
		maxSamples:    maxSamples,
		rttThreshold:  1.5,
		lossThreshold: 0.05,
	}
}

// RecordRTT 记录 RTT 样本
func (d *Detector) RecordRTT(rtt time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.rttSamples) >= d.maxSamples {
		d.rttSamples = d.rttSamples[1:]
	}
	d.rttSamples = append(d.rttSamples, rtt)
}

// RecordLoss 记录丢包事件
func (d *Detector) RecordLoss(lost bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.totalCount++
	if lost {
		d.lossCount++
	}
}

// ShouldSwitch 判断是否应该切换
func (d *Detector) ShouldSwitch() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.rttSamples) < 2 {
		return false, ""
	}

	var sum time.Duration
	for _, s := range d.rttSamples {
		sum += s
	}
	avg := sum / time.Duration(len(d.rttSamples))
	latest := d.rttSamples[len(d.rttSamples)-1]

	if avg > 0 && float64(latest) > float64(avg)*d.rttThreshold {
		return true, "RTT spike"
	}

	if d.totalCount >= 10 {
		lossRate := float64(d.lossCount) / float64(d.totalCount)
		if lossRate > d.lossThreshold {
			return true, "high loss rate"
		}
	}

	return false, ""
}

// Reset 重置检测器状态
func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rttSamples = d.rttSamples[:0]
	d.lossCount = 0
	d.totalCount = 0
}

// MigrationState 迁移状态
type MigrationState int

const (
	StateStable    MigrationState = iota // 正常单连接运行
	StateMigrating                       // 正在建立新连接
	StateDual                            // 双连接并行（新旧同时运行）
	StateSwitched                        // 已切换到新连接
)

func (s MigrationState) String() string {
	switch s {
	case StateStable:
		return "stable"
	case StateMigrating:
		return "migrating"
	case StateDual:
		return "dual"
	case StateSwitched:
		return "switched"
	default:
		return "unknown"
	}
}

// MigrationEngine 双连接并行迁移引擎
type MigrationEngine struct {
	mu          sync.Mutex
	state       MigrationState
	oldConn     net.Conn
	newConn     net.Conn
	onSwitch    func(oldPath, newPath string)
	oldPath     string
	newPath     string
	readyCh     chan struct{}
	drainDoneCh chan struct{}
}

// NewMigrationEngine 创建无感迁移引擎
func NewMigrationEngine() *MigrationEngine {
	return &MigrationEngine{
		state:       StateStable,
		readyCh:     make(chan struct{}, 1),
		drainDoneCh: make(chan struct{}, 1),
	}
}

func (e *MigrationEngine) SetPrimary(conn net.Conn, path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.oldConn = conn
	e.oldPath = path
	e.state = StateStable
}

func (e *MigrationEngine) OnSwitch(fn func(oldPath, newPath string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onSwitch = fn
}

func (e *MigrationEngine) StartMigration(newConn net.Conn, newPath string) {
	e.mu.Lock()
	e.newConn = newConn
	e.newPath = newPath
	e.state = StateMigrating
	e.mu.Unlock()

	log.Printf("[MIGRATION] Starting migration: %s -> %s", e.oldPath, newPath)
	select {
	case e.readyCh <- struct{}{}:
	default:
	}
}

func (e *MigrationEngine) Ready() <-chan struct{} {
	return e.readyCh
}

func (e *MigrationEngine) ActivateNew() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == StateMigrating {
		e.state = StateDual
		log.Printf("[MIGRATION] Dual mode active: old=%s new=%s", e.oldPath, e.newPath)
	}
}

func (e *MigrationEngine) DrainOld(ctx context.Context) {
	e.mu.Lock()
	old := e.oldConn
	oldPath := e.oldPath
	e.mu.Unlock()

	select {
	case <-e.drainDoneCh:
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
	}

	if old != nil {
		old.Close()
	}

	e.mu.Lock()
	e.oldConn = e.newConn
	e.oldPath = e.newPath
	e.newConn = nil
	e.state = StateSwitched
	e.mu.Unlock()

	log.Printf("[MIGRATION] Switched to %s (old=%s closed)", e.oldPath, oldPath)

	if e.onSwitch != nil {
		e.onSwitch(oldPath, e.newPath)
	}
}

func (e *MigrationEngine) NewConn() net.Conn {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.newConn
}

func (e *MigrationEngine) OldConn() net.Conn {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.oldConn
}

func (e *MigrationEngine) IsDual() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state == StateDual
}

func (e *MigrationEngine) SignalDrainDone() {
	select {
	case e.drainDoneCh <- struct{}{}:
	default:
	}
}
