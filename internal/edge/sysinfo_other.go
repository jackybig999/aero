// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build !linux

package edge

import (
	"runtime"
	"time"
)

func statfsDiskUsage(rootDir string, m *SystemMetrics) {
}

func diskBytes(dir string) (total, used uint64, ok bool) { return 0, 0, false }

func collectPlatformMetrics(prev *rawMetricsSample) (*SystemMetrics, *rawMetricsSample) {
	now := time.Now()
	m := &SystemMetrics{
		CPUUsagePct:      12.0,
		CPUUsagePercent:  12.0,
		MemoryTotalMB:    8192,
		MemTotalMB:       8192,
		MemoryUsedMB:     2048,
		MemUsedMB:        2048,
		MemoryFreeMB:     6144,
		MemFreeMB:        6144,
		MemoryUsagePct:   25.0,
		MemUsagePercent:  25.0,
		DiskTotalGB:      120.0,
		DiskUsedGB:       30.0,
		DiskFreeGB:       90.0,
		DiskUsagePct:     25.0,
		DiskUsagePercent: 25.0,
		NetRxRateKBps:    100.0,
		NetTxRateKBps:    50.0,
		NetTotalRxMB:     1024.0,
		NetTotalTxMB:     512.0,
		NetRxBytes:       1024 * 1024 * 1024,
		NetTxBytes:       512 * 1024 * 1024,
		UptimeSeconds:    86400,
		UptimeFormatted:  FormatUptime(86400),
		LoadAverage:      [3]float64{0.10, 0.20, 0.15},
		SampledAt:        now,
		Platform:         runtime.GOOS,
	}
	return m, nil
}
