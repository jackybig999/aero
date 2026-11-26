// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessCPUSecondsIncreases(t *testing.T) {
	a, ok := processCPUSeconds()
	if !ok {
		t.Skip("process CPU time unavailable")
	}
	end := time.Now().Add(50 * time.Millisecond)
	for x := 0; time.Now().Before(end); x++ { // 烧一点 CPU
		_ = x * x
	}
	b, _ := processCPUSeconds()
	if b <= a {
		t.Fatalf("cpu seconds did not increase: %v -> %v", a, b)
	}
}

func TestCaptureProfileWritesPrivateFilesAndPrunes(t *testing.T) {
	old := selfProfileFor
	selfProfileFor = 50 * time.Millisecond
	defer func() { selfProfileFor = old }()
	dir := t.TempDir()
	for i := 0; i < selfKeepFiles+3; i++ { // 先放一批旧文件，抓取后应只保留最新的 selfKeepFiles 份
		name := filepath.Join(dir, "cpu-2020010"+string(rune('0'+i))+"-000000.pprof")
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	captureProfile(context.Background(), dir)
	cpus, _ := filepath.Glob(filepath.Join(dir, "cpu-*.pprof"))
	if len(cpus) != selfKeepFiles {
		t.Fatalf("kept %d cpu profiles, want %d", len(cpus), selfKeepFiles)
	}
	gs, _ := filepath.Glob(filepath.Join(dir, "goroutines-*.txt"))
	if len(gs) != 1 {
		t.Fatalf("goroutine dumps = %d, want 1", len(gs))
	}
	if st, err := os.Stat(gs[0]); err != nil || st.Size() == 0 {
		t.Fatalf("goroutine dump empty: %v", err)
	}
}

func TestStartSelfMonitorDisabledAndStops(t *testing.T) {
	t.Setenv("AERO_SELFMON", "0")
	StartSelfMonitor(context.Background(), t.TempDir()) // 关闭时不启动协程，也不应 panic
	t.Setenv("AERO_SELFMON", "")
	ctx, cancel := context.WithCancel(context.Background())
	StartSelfMonitor(ctx, t.TempDir())
	cancel()
}
