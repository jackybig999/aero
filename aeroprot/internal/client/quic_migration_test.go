// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type mockPathController struct {
	probeFunc  func(ctx context.Context) error
	switchFunc func() error
	closeFunc  func() error

	probeCalled  atomic.Bool
	switchCalled atomic.Bool
	closeCalled  atomic.Bool
}

func (m *mockPathController) Probe(ctx context.Context) error {
	m.probeCalled.Store(true)
	if m.probeFunc != nil {
		return m.probeFunc(ctx)
	}
	return nil
}

func (m *mockPathController) Switch() error {
	m.switchCalled.Store(true)
	if m.switchFunc != nil {
		return m.switchFunc()
	}
	return nil
}

func (m *mockPathController) Close() error {
	m.closeCalled.Store(true)
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

type mockMigrationCloser struct {
	closed atomic.Bool
}

func (m *mockMigrationCloser) Close() error {
	m.closed.Store(true)
	return nil
}

// TestQUICMigration_StateStrings 状态机字符串表述覆盖
func TestQUICMigration_StateStrings(t *testing.T) {
	tests := []struct {
		state MigrationState
		want  string
	}{
		{MigrationStateIdle, "Idle"},
		{MigrationStateProbing, "Probing"},
		{MigrationStateSwitched, "Switched"},
		{MigrationStateFailed, "Failed"},
		{MigrationStateRedialing, "Redialing"},
		{MigrationState(99), "MigrationState(99)"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("MigrationState(%d).String() = %q, want %q", int32(tt.state), got, tt.want)
		}
	}
}

// TestQUICMigration_Success 验证成功漫游、状态流转以及安全排空
func TestQUICMigration_Success(t *testing.T) {
	cfg := DefaultMigrationConfig()
	cfg.DebounceWindow = 20 * time.Millisecond
	cfg.DrainBaseGrace = 40 * time.Millisecond
	cfg.DefaultFallbackRTT = 10 * time.Millisecond

	migrator := NewQUICMigrator(&cfg)
	if migrator.State() != MigrationStateIdle {
		t.Fatalf("expected initial state Idle, got %v", migrator.State())
	}

	mockPath := &mockPathController{}
	oldPath := &mockPathController{}
	oldTr := &mockMigrationCloser{}
	oldConn := &mockMigrationCloser{}

	drainOpts := DrainOptions{
		OldPath:       oldPath,
		OldTransport:  oldTr,
		OldPacketConn: oldConn,
		SmoothedRTT:   10 * time.Millisecond,
	}

	ctx := context.Background()
	err := migrator.MigrateWithController(ctx, mockPath, drainOpts, func() bool { return true })
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	if migrator.State() != MigrationStateSwitched {
		t.Fatalf("expected state Switched, got %v", migrator.State())
	}
	if !mockPath.probeCalled.Load() {
		t.Errorf("expected probe to be called")
	}
	if !mockPath.switchCalled.Load() {
		t.Errorf("expected switch to be called")
	}
	if !oldPath.closeCalled.Load() {
		t.Errorf("expected old path to be closed immediately")
	}

	// 此时排空延迟为 2*10ms + 40ms = 60ms；刚完成迁移时底层套接字不应立即关闭
	if oldConn.closed.Load() {
		t.Errorf("expected old socket not to be closed immediately during drain grace period")
	}

	// 等待排空完成
	migrator.drainWG.Wait()
	if !oldConn.closed.Load() {
		t.Errorf("expected old socket to be closed after drain grace period")
	}
	if !oldTr.closed.Load() {
		t.Errorf("expected old transport to be closed after drain grace period")
	}

	att, succ, fail, red, th := migrator.Stats()
	if att != 1 || succ != 1 || fail != 0 || red != 0 || th != 0 {
		t.Errorf("unexpected stats: att=%d, succ=%d, fail=%d, red=%d, th=%d", att, succ, fail, red, th)
	}
}

// TestQUICMigration_Debounce 验证 150ms 防抖节流
func TestQUICMigration_Debounce(t *testing.T) {
	cfg := DefaultMigrationConfig()
	cfg.DebounceWindow = 100 * time.Millisecond
	migrator := NewQUICMigrator(&cfg)

	mockPath1 := &mockPathController{}
	err1 := migrator.MigrateWithController(context.Background(), mockPath1, DrainOptions{}, func() bool { return true })
	if err1 != nil {
		t.Fatalf("first migration unexpected error: %v", err1)
	}

	// 立即发起第二次漫游，预期命中节流
	mockPath2 := &mockPathController{}
	err2 := migrator.MigrateWithController(context.Background(), mockPath2, DrainOptions{}, func() bool { return true })
	if !errors.Is(err2, ErrMigrationThrottled) {
		t.Fatalf("expected ErrMigrationThrottled, got: %v", err2)
	}

	// 等待窗口过期
	time.Sleep(110 * time.Millisecond)

	mockPath3 := &mockPathController{}
	err3 := migrator.MigrateWithController(context.Background(), mockPath3, DrainOptions{}, func() bool { return true })
	if err3 != nil {
		t.Fatalf("third migration unexpected error: %v", err3)
	}
}

// TestQUICMigration_ProbeFailure 回退到原有路径
func TestQUICMigration_ProbeFailure(t *testing.T) {
	cfg := DefaultMigrationConfig()
	cfg.DebounceWindow = 10 * time.Millisecond
	migrator := NewQUICMigrator(&cfg)

	mockPath := &mockPathController{
		probeFunc: func(ctx context.Context) error {
			return errors.New("simulated probe network timeout")
		},
	}

	err := migrator.MigrateWithController(context.Background(), mockPath, DrainOptions{}, func() bool { return true })
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if migrator.State() != MigrationStateFailed {
		t.Fatalf("expected state Failed, got %v", migrator.State())
	}
	if !mockPath.closeCalled.Load() {
		t.Errorf("expected failed new path to be closed")
	}
}

// TestQUICMigration_RedialTrigger 验证原连接断死时探针失败触发重拨降级
func TestQUICMigration_RedialTrigger(t *testing.T) {
	cfg := DefaultMigrationConfig()
	cfg.DebounceWindow = 10 * time.Millisecond
	migrator := NewQUICMigrator(&cfg)

	mockPath := &mockPathController{
		probeFunc: func(ctx context.Context) error {
			return errors.New("timeout")
		},
	}

	// 原连接已断死
	parentAlive := false
	err := migrator.MigrateWithController(context.Background(), mockPath, DrainOptions{}, func() bool { return parentAlive })
	if err == nil || !errors.Is(err, ErrNeedRedial) {
		t.Fatalf("expected ErrNeedRedial, got: %v", err)
	}

	if migrator.State() != MigrationStateRedialing {
		t.Fatalf("expected state Redialing, got %v", migrator.State())
	}
}
