// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSysinfo_Linux_ProcParsing(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Write mock stat
	statData := "cpu  2255 34 2290 22625563 6290 127 456 0 0 0\n"
	if err := os.WriteFile(filepath.Join(tempDir, "stat"), []byte(statData), 0o600); err != nil {
		t.Fatalf("write stat: %v", err)
	}

	// 2. Write mock meminfo
	memData := `MemTotal:        8171052 kB
MemFree:         1048576 kB
MemAvailable:    4194304 kB
Buffers:          524288 kB
Cached:          2097152 kB
`
	if err := os.WriteFile(filepath.Join(tempDir, "meminfo"), []byte(memData), 0o600); err != nil {
		t.Fatalf("write meminfo: %v", err)
	}

	// 3. Write mock net/dev
	if err := os.MkdirAll(filepath.Join(tempDir, "net"), 0o755); err != nil {
		t.Fatalf("mkdir net: %v", err)
	}
	netData := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000       10    0    0    0     0          0         0     1000       10    0    0    0     0       0          0
  eth0: 10485760  2000    0    0    0     0          0         0 20971520  4000    0    0    0     0       0          0
`
	if err := os.WriteFile(filepath.Join(tempDir, "net", "dev"), []byte(netData), 0o600); err != nil {
		t.Fatalf("write net/dev: %v", err)
	}

	// 4. Write mock uptime
	uptimeData := "86420.50 172841.00\n"
	if err := os.WriteFile(filepath.Join(tempDir, "uptime"), []byte(uptimeData), 0o600); err != nil {
		t.Fatalf("write uptime: %v", err)
	}

	// 5. Write mock loadavg
	loadData := "0.15 0.25 0.35 1/200 12345\n"
	if err := os.WriteFile(filepath.Join(tempDir, "loadavg"), []byte(loadData), 0o600); err != nil {
		t.Fatalf("write loadavg: %v", err)
	}

	stats, err := CollectSysInfoFrom(tempDir, tempDir)
	if err != nil {
		t.Fatalf("CollectSysInfoFrom: %v", err)
	}

	// Assertions aligned with specification in Miner Hand-off §8.1
	if stats.MemTotalMB != 7979 {
		t.Errorf("expected MemTotalMB 7979, got %d", stats.MemTotalMB)
	}
	if stats.MemUsedMB != 3883 {
		t.Errorf("expected MemUsedMB 3883, got %d", stats.MemUsedMB)
	}
	if stats.UptimeSeconds != 86420 {
		t.Errorf("expected UptimeSeconds 86420, got %d", stats.UptimeSeconds)
	}
	if stats.UptimeFormatted != "1d 0h 0m" {
		t.Errorf("expected UptimeFormatted '1d 0h 0m', got %q", stats.UptimeFormatted)
	}
	if stats.NetRxBytes != 10485760 {
		t.Errorf("expected NetRxBytes 10485760, got %d", stats.NetRxBytes)
	}
	if stats.NetTxBytes != 20971520 {
		t.Errorf("expected NetTxBytes 20971520, got %d", stats.NetTxBytes)
	}
	if stats.LoadAverage[0] != 0.15 || stats.LoadAverage[1] != 0.25 || stats.LoadAverage[2] != 0.35 {
		t.Errorf("unexpected LoadAverage: %v", stats.LoadAverage)
	}
}

func TestSysinfo_MetricsCollector_Lifecycle(t *testing.T) {
	collector := NewMetricsCollector(50 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector.Start(ctx)

	// Wait for at least one sample
	time.Sleep(120 * time.Millisecond)

	m := collector.GetMetrics()
	if m == nil {
		t.Fatal("expected non-nil metrics")
	}
	if m.Platform == "" {
		t.Errorf("expected non-empty platform")
	}

	collector.Stop()
}

func TestSysinfo_FormatUptime(t *testing.T) {
	tests := []struct {
		sec  uint64
		want string
	}{
		{0, "0d 0h 0m"},
		{59, "0d 0h 0m"},
		{60, "0d 0h 1m"},
		{3600, "0d 1h 0m"},
		{86400, "1d 0h 0m"},
		{90061, "1d 1h 1m"},
	}
	for _, tc := range tests {
		got := FormatUptime(tc.sec)
		if got != tc.want {
			t.Errorf("FormatUptime(%d) = %q, want %q", tc.sec, got, tc.want)
		}
	}
}
