//go:build linux && !android

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// 网关缓存期内发生的网络变化也必须被检测到：evaluate 读取前要先失效缓存。
func TestNetmonEvaluateBypassesGatewayCache(t *testing.T) {
	// 用假 ip 命令提供“真实路由表”，不依赖也不触碰宿主网络配置
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'default via 10.9.8.7 dev eth9'\n"
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ip: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	gw, ifName := "10.9.8.7", "eth9"
	t.Cleanup(invalidateGatewayCache)

	// 构造“缓存期内的旧网关”：缓存里是旧值且仍新鲜，真实路由表已经是另一个值
	gwCacheMu.Lock()
	lastGW = cachedGateway{gw: "192.0.2.1", ifIndex: "old-iface", updated: time.Now()}
	gwCacheMu.Unlock()

	w := newDebounceWatcher()
	w.lastFingerprint = "192.0.2.1@old-iface"
	var got atomic.Value
	var calls atomic.Int32
	w.onChange = func(newGW, newIf string) {
		got.Store(newGW + "@" + newIf)
		calls.Add(1)
	}

	w.evaluate()

	if calls.Load() != 1 {
		t.Fatalf("expected change detected within gateway cache window, callbacks=%d", calls.Load())
	}
	if v, _ := got.Load().(string); v != gw+"@"+ifName {
		t.Fatalf("expected fingerprint %q, got %q", gw+"@"+ifName, v)
	}
}

// engine 会对同一个监控器反复 Start/Stop：重复 start 不重复起 loop，
// stop 幂等，stop 之后可以重新 start 且不 panic。
func TestNetmonDebounceWatcherRestart(t *testing.T) {
	w := newDebounceWatcher()
	w.debounce = 10 * time.Millisecond

	w.stop() // 未启动时 stop 为空操作
	for i := 0; i < 3; i++ {
		w.start(func(string, string) {})
		w.start(func(string, string) {}) // 重复 start 无副作用
		w.trigger()
		w.stop()
		w.stop() // 幂等
	}
}
