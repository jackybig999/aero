// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build linux

package edge

import "golang.org/x/sys/unix"

func statfsDiskUsage(rootDir string, m *SystemMetrics) {
	var stat unix.Statfs_t
	if err := unix.Statfs(rootDir, &stat); err == nil && stat.Blocks > 0 {
		bsize := uint64(stat.Bsize)
		totalBytes := stat.Blocks * bsize
		freeBytes := stat.Bavail * bsize
		usedBytes := uint64(0)
		if totalBytes >= freeBytes {
			usedBytes = totalBytes - freeBytes
		}
		m.DiskTotalGB = round2(float64(totalBytes) / (1024.0 * 1024.0 * 1024.0))
		m.DiskFreeGB = round2(float64(freeBytes) / (1024.0 * 1024.0 * 1024.0))
		m.DiskUsedGB = round2(float64(usedBytes) / (1024.0 * 1024.0 * 1024.0))
		if totalBytes > 0 {
			m.DiskUsagePct = round2((float64(usedBytes) / float64(totalBytes)) * 100.0)
			m.DiskUsagePercent = m.DiskUsagePct
		}
	}
}

func collectPlatformMetrics(prev *rawMetricsSample) (*SystemMetrics, *rawMetricsSample) {
	return collectLinuxMetricsFrom("/proc", "/", prev)
}
