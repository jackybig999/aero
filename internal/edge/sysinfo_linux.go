// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build linux

package edge

import "golang.org/x/sys/unix"

// diskBytes 返回 dir 所在文件系统的总字节与已用字节（只读）。
func diskBytes(dir string) (total, used uint64, ok bool) {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil || stat.Blocks == 0 {
		return 0, 0, false
	}
	bsize := uint64(stat.Bsize)
	total, free := stat.Blocks*bsize, stat.Bavail*bsize
	if total >= free {
		used = total - free
	}
	return total, used, true
}

func statfsDiskUsage(rootDir string, m *SystemMetrics) {
	total, used, ok := diskBytes(rootDir)
	if !ok {
		return
	}
	const gb = 1024.0 * 1024.0 * 1024.0
	m.DiskTotalGB = round2(float64(total) / gb)
	m.DiskFreeGB = round2(float64(total-used) / gb)
	m.DiskUsedGB = round2(float64(used) / gb)
	m.DiskUsagePct = round2((float64(used) / float64(total)) * 100.0)
	m.DiskUsagePercent = m.DiskUsagePct
}

func collectPlatformMetrics(prev *rawMetricsSample) (*SystemMetrics, *rawMetricsSample) {
	return collectLinuxMetricsFrom("/proc", "/", prev)
}
