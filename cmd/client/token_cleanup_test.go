// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCleanOrphanTokens(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		"session-100.token", // 已死亡：删除
		"session-200.token", // 存活：保留
		"session-300.token", // 自身：保留
		"session-abc.token", // 无法解析：保留
		"session-0.token",   // 非法 PID：保留
		"other-400.token",   // 非 token 文件：保留
		"session-500.txt",   // 后缀不符：保留
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	alive := func(pid int) bool { return pid == 200 }
	cleanOrphanTokens(dir, 300, alive)

	for _, f := range files {
		_, err := os.Stat(filepath.Join(dir, f))
		gone := os.IsNotExist(err)
		if want := f == "session-100.token"; gone != want {
			t.Errorf("%s: removed=%v want %v", f, gone, want)
		}
	}
}

func TestCleanOrphanTokensMissingDir(t *testing.T) {
	cleanOrphanTokens(filepath.Join(t.TempDir(), "nope"), 1, func(int) bool { return false })
}

func TestOnceShutdown(t *testing.T) {
	var n atomic.Int32
	sd := newOnceShutdown(func() { n.Add(1) })
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); sd() }()
	}
	wg.Wait()
	sd()
	if got := n.Load(); got != 1 {
		t.Fatalf("shutdown ran %d times, want 1", got)
	}
}

func TestRemoveOwnToken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "session-1.token")
	if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	setOwnTokenPath(p)
	defer setOwnTokenPath("")
	removeOwnToken()
	removeOwnToken() // 幂等
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("token still exists: %v", err)
	}
}
