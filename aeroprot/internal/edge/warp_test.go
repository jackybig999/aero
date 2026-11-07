// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWarpInstaller_BypassProtection(t *testing.T) {
	dg := NewDialGuard(64)
	defer dg.Close()
	installer := NewWarpInstaller(dg)

	var execCalls atomic.Int32
	installer.SetHooks(
		func(ctx context.Context, name string, args ...string) ([]byte, error) {
			execCalls.Add(1)
			return []byte("ok"), nil
		},
		func(addr string) bool {
			// Mock port 40000 is open
			return addr == "127.0.0.1:40000"
		},
		func(addr string) bool {
			// Mock trace has warp=on
			return true
		},
		func() bool {
			return true
		},
		func() bool {
			return true
		},
	)

	status, bypassed, err := installer.StartInstall(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status != "already_active" {
		t.Errorf("expected status 'already_active', got %q", status)
	}
	if !bypassed {
		t.Errorf("expected bypassed true, got false")
	}

	// Crucial rule: Apt / systemctl must NOT be executed if bypassed
	if calls := execCalls.Load(); calls != 0 {
		t.Errorf("expected 0 command executions on bypass, got %d", calls)
	}

	st := installer.GetStatus()
	if !st.Bypassed {
		t.Errorf("expected status.Bypassed true")
	}
	if st.Progress != 100 {
		t.Errorf("expected Progress 100 on bypass, got %d", st.Progress)
	}
	if len(st.Logs) == 0 {
		t.Errorf("expected bypass log entry, got empty logs")
	}
}

func TestWarpInstaller_FullPipeline(t *testing.T) {
	dg := NewDialGuard(64)
	defer dg.Close()
	installer := NewWarpInstaller(dg)

	var executedCommands []string
	var mu sync.Mutex

	portActive := false
	installer.SetHooks(
		func(ctx context.Context, name string, args ...string) ([]byte, error) {
			mu.Lock()
			cmdStr := name + " " + strings.Join(args, " ")
			executedCommands = append(executedCommands, cmdStr)
			mu.Unlock()

			if strings.Contains(cmdStr, "warp-cli") || strings.Contains(cmdStr, "systemctl") {
				portActive = true
			}
			return []byte("success"), nil
		},
		func(addr string) bool {
			return portActive
		},
		func(addr string) bool {
			return false // initially not bypassed
		},
		func() bool {
			return true
		},
		func() bool {
			return true // root
		},
	)

	status, bypassed, err := installer.StartInstall(context.Background())
	if err != nil {
		t.Fatalf("StartInstall: %v", err)
	}
	if status != "running" {
		t.Errorf("expected status 'running', got %q", status)
	}
	if bypassed {
		t.Errorf("expected bypassed false")
	}

	// Wait for pipeline completion
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := installer.GetStatus()
		if st.Status == "success" || st.Status == "failed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	st := installer.GetStatus()
	if st.Status != "success" {
		t.Fatalf("expected pipeline status 'success', got %q (error: %s)", st.Status, st.Error)
	}
	if st.Progress != 100 {
		t.Errorf("expected Progress 100, got %d", st.Progress)
	}

	mu.Lock()
	cmds := executedCommands
	mu.Unlock()

	if len(cmds) < 4 {
		t.Errorf("expected at least 4 commands executed, got %d: %v", len(cmds), cmds)
	}
}

func TestWarpInstaller_ConcurrentInstallConflict(t *testing.T) {
	dg := NewDialGuard(64)
	defer dg.Close()
	installer := NewWarpInstaller(dg)

	blockCh := make(chan struct{})
	installer.SetHooks(
		func(ctx context.Context, name string, args ...string) ([]byte, error) {
			<-blockCh
			return []byte("ok"), nil
		},
		func(addr string) bool { return false },
		func(addr string) bool { return false },
		func() bool { return true },
		func() bool { return true },
	)

	// First call starts pipeline
	_, _, err := installer.StartInstall(context.Background())
	if err != nil {
		t.Fatalf("StartInstall #1: %v", err)
	}

	// Second concurrent call should immediately return conflict
	_, _, err2 := installer.StartInstall(context.Background())
	if err2 == nil || err2 != ErrInstallInProgress {
		t.Errorf("expected ErrInstallInProgress on concurrent start, got: %v", err2)
	}

	close(blockCh)
}

func TestWarpInstaller_UninstallPipeline(t *testing.T) {
	dg := NewDialGuard(64)
	defer dg.Close()
	installer := NewWarpInstaller(dg)

	// Pre-set proxy
	dg.SetWarpProxy("127.0.0.1:40000", true)

	var executedCmds []string
	var mu sync.Mutex

	installer.SetHooks(
		func(ctx context.Context, name string, args ...string) ([]byte, error) {
			mu.Lock()
			executedCmds = append(executedCmds, fmt.Sprintf("%s %s", name, strings.Join(args, " ")))
			mu.Unlock()
			return []byte("ok"), nil
		},
		func(addr string) bool { return false },
		func(addr string) bool { return false },
		func() bool { return false },
		func() bool { return true },
	)

	status, err := installer.StartUninstall(context.Background())
	if err != nil {
		t.Fatalf("StartUninstall: %v", err)
	}
	if status != "running" {
		t.Errorf("expected status 'running', got %s", status)
	}

	// Wait for pipeline to finish
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st := installer.GetStatus()
		if st.Status == "idle" || st.Status == "failed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	st := installer.GetStatus()
	if st.Status != "idle" {
		t.Fatalf("expected uninstall status 'idle', got: %+v", st)
	}

	// Verify WARP proxy was cleared in dialGuard
	proxy, all, enabled, _ := dg.GetWarpStatus()
	if enabled || all || proxy != "" {
		t.Errorf("expected dialGuard warp proxy disabled, got proxy=%s, enabled=%v", proxy, enabled)
	}
}

func TestDialGuard_WarpToggle_RaceSafety(t *testing.T) {
	dg := NewDialGuard(128)
	dg.AllowLocal = true
	defer dg.Close()

	// Spin up a mock local target server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	targetAddr := ln.Addr().String()

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// 1. Toggler goroutine dynamically flipping SetWarpProxy
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for {
			select {
			case <-stopCh:
				return
			default:
				if toggle {
					dg.SetWarpProxy("127.0.0.1:40000", false)
				} else {
					dg.SetWarpProxy("", false)
				}
				toggle = !toggle
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	// 2. 50 concurrent dialing goroutines
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				c, err := dg.DialTimeout("tcp", targetAddr, 100*time.Millisecond)
				if err == nil {
					_ = c.Close()
				}
				_, _, _, _ = dg.GetWarpStatus()
			}
		}()
	}

	// Let them run concurrently under -race
	time.Sleep(300 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}

func TestDialGuard_AIFailClosed(t *testing.T) {
	dg := NewDialGuard(64)
	defer dg.Close()

	// Configure WARP to an unreachable local port
	dg.SetWarpProxy("127.0.0.1:59998", false)

	// Dialing an AI domain must fail closed immediately
	_, err := dg.DialTimeout("tcp", "chatgpt.com:443", 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected error dialing AI domain with WARP proxy down, got nil")
	}
	if !strings.Contains(err.Error(), "AERO_WARP_FAIL_CLOSED") {
		t.Errorf("expected AERO_WARP_FAIL_CLOSED error, got: %v", err)
	}

	// Dialing a regular non-AI target with AllowLocal=true should fallback to direct dial
	dg.AllowLocal = true
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	c, err := dg.DialTimeout("tcp", targetLn.Addr().String(), 500*time.Millisecond)
	if err != nil {
		t.Errorf("expected non-AI domain fallback to direct dial, got error: %v", err)
	} else {
		_ = c.Close()
	}
}

func TestDialGuard_AIFailClosed_TrailingDotFQDN(t *testing.T) {
	dg := NewDialGuard(64)
	defer dg.Close()
	dg.AllowLocal = false

	// Dead WARP proxy port
	dg.SetWarpProxy("127.0.0.1:59998", false)

	aiFQDNs := []string{
		"chatgpt.com.:443",
		"ChatGPT.COM.:443",
		"openai.com.:443",
		"api.openai.com.:443",
		"claude.ai.:443",
		"gemini.google.com.:443",
		"deepmind.google.:443",
		"perplexity.ai.:443",
		"x.ai.:443",
	}

	for _, target := range aiFQDNs {
		conn, err := dg.DialTimeout("tcp", target, 200*time.Millisecond)
		if conn != nil {
			_ = conn.Close()
			t.Fatalf("SECURITY VIOLATION: direct dial succeeded for AI domain %s with dead WARP!", target)
		}
		if err == nil {
			t.Fatalf("SECURITY VIOLATION: expected error dialing %s, got nil", target)
		}
		if !strings.Contains(err.Error(), "AERO_WARP_FAIL_CLOSED") {
			t.Fatalf("CONTRACT VIOLATION: expected error containing 'AERO_WARP_FAIL_CLOSED' for %s, got: %v", target, err)
		}
	}

	// Verify unit behavior of isTargetAIDomain
	tableTests := []struct {
		addr     string
		expected bool
	}{
		{"chatgpt.com.:443", true},
		{"ChatGPT.COM.:443", true},
		{"chatgpt.com.", true},
		{"api.openai.com.:443", true},
		{"sub.claude.ai.:443", true},
		{"deepmind.google.:443", true},
		{"example.com.:80", false},
		{"1.1.1.1:443", false},
		{".:443", false},
		{"", false},
	}
	for _, tc := range tableTests {
		if got := isTargetAIDomain(tc.addr); got != tc.expected {
			t.Errorf("isTargetAIDomain(%q) = %v, expected %v", tc.addr, got, tc.expected)
		}
	}
}

func TestDialGuard_ConcurrentSetWarpProxy_RaceFree(t *testing.T) {
	dg := NewDialGuard(64)
	defer dg.Close()

	var wg sync.WaitGroup
	const callers = 20
	const iters = 100

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if id%2 == 0 {
					dg.SetWarpProxy(fmt.Sprintf("127.0.0.1:%d", 40000+id), false)
				} else {
					dg.SetWarpProxy("", true)
				}
				_, _, _, _ = dg.GetWarpStatus()
			}
		}(i)
	}
	wg.Wait()
}
