// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

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

	// Dead WARP proxy port with WarpAll=true (default)
	dg.SetWarpProxy("127.0.0.1:59998", true)

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

// WARP 开关持久化（ADR-0012 第 6 条）：开启写入 warp_proxy/warp_all，关闭显式写空，重启后保持。
func TestSetWarpEgressPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.json")
	if err := os.WriteFile(path, []byte(`{"domain":"n.example","listen":":2083"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: ServerConfig{ConfigPath: path, Domain: "n.example", Listen: ":2083"}, dialGuard: NewDialGuard(4)}
	defer s.dialGuard.Close()
	read := func() map[string]any {
		var m map[string]any
		b, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(b, &m)
		}
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if err := s.SetWarpEgress(true, false); err != nil {
		t.Fatal(err)
	}
	if m := read(); m["warp_proxy"] != warpLocalProxy || m["warp_all"] != false || m["listen"] != ":2083" {
		t.Fatalf("after enable: %v", m)
	}
	if proxy, all, enabled, _ := s.dialGuard.GetWarpStatus(); !enabled || proxy != warpLocalProxy || all {
		t.Fatalf("dial guard not updated: proxy=%q all=%v enabled=%v", proxy, all, enabled)
	}
	if err := s.SetWarpEgress(false, true); err != nil {
		t.Fatal(err)
	}
	if m := read(); m["warp_proxy"] != "" || m["warp_all"] != false {
		t.Fatalf("after disable: %v", m)
	}
	if _, _, enabled, _ := s.dialGuard.GetWarpStatus(); enabled {
		t.Fatal("dial guard still routes via WARP after disable")
	}
}

// edge 不再安装或卸载 WARP：旧接口返回 410 与操作说明。
func TestConsoleWarpInstallEndpointsGone(t *testing.T) {
	h := NewConsoleHandler("console_key_0123456789", nil, nil, nil, nil, nil, nil, nil)
	for _, path := range []string{"/console/api/warp/install", "/console/api/warp/uninstall", "/console/api/warp/logs"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("X-Aero-Admin-Key", "console_key_0123456789")
		rec := httptest.NewRecorder()
		if !h.TryServe(rec, req) {
			t.Fatalf("%s not handled", path)
		}
		if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "官方") {
			t.Errorf("%s = %d %s, want 410 with guidance", path, rec.Code, rec.Body.String())
		}
	}
}
