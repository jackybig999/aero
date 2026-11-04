// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// SystemMetrics represents a snapshot of VPS hardware and OS vital signs.
type SystemMetrics struct {
	CPUUsagePct      float64    `json:"cpu_usage_pct"`
	CPUUsagePercent  float64    `json:"cpu_usage_percent"`
	MemoryTotalMB    uint64     `json:"memory_total_mb"`
	MemTotalMB       uint64     `json:"mem_total_mb"`
	MemoryUsedMB     uint64     `json:"memory_used_mb"`
	MemUsedMB        uint64     `json:"mem_used_mb"`
	MemoryFreeMB     uint64     `json:"memory_free_mb"`
	MemFreeMB        uint64     `json:"mem_free_mb"`
	MemoryUsagePct   float64    `json:"memory_usage_pct"`
	MemUsagePercent  float64    `json:"mem_usage_percent"`
	DiskTotalGB      float64    `json:"disk_total_gb"`
	DiskUsedGB       float64    `json:"disk_used_gb"`
	DiskFreeGB       float64    `json:"disk_free_gb"`
	DiskUsagePct     float64    `json:"disk_usage_pct"`
	DiskUsagePercent float64    `json:"disk_usage_percent"`
	NetRxRateKBps    float64    `json:"net_rx_rate_kbps"`
	NetTxRateKBps    float64    `json:"net_tx_rate_kbps"`
	NetTotalRxMB     float64    `json:"net_total_rx_mb"`
	NetTotalTxMB     float64    `json:"net_total_tx_mb"`
	NetRxBytes       uint64     `json:"net_rx_bytes"`
	NetTxBytes       uint64     `json:"net_tx_bytes"`
	UptimeSeconds    uint64     `json:"uptime_seconds"`
	UptimeFormatted  string     `json:"uptime_formatted"`
	LoadAverage      [3]float64 `json:"load_average"`
	SampledAt        time.Time  `json:"sampled_at"`
	Platform         string     `json:"platform"`
}

type rawMetricsSample struct {
	cpuTotal uint64
	cpuIdle  uint64
	rxBytes  uint64
	txBytes  uint64
	sampleAt time.Time
}

// MetricsCollector manages continuous background sampling and atomic caching.
type MetricsCollector struct {
	mu        sync.Mutex
	cached    atomic.Pointer[SystemMetrics]
	prevRaw   *rawMetricsSample
	stopCh    chan struct{}
	closeOnce sync.Once
	interval  time.Duration
}

// NewMetricsCollector creates a metrics collector; interval <= 0 defaults to 2 seconds.
func NewMetricsCollector(interval time.Duration) *MetricsCollector {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	mc := &MetricsCollector{
		stopCh:   make(chan struct{}),
		interval: interval,
	}
	// Initial sample
	metrics, raw := collectPlatformMetrics(nil)
	mc.cached.Store(metrics)
	mc.prevRaw = raw
	return mc
}

// Start begins the background collection loop.
func (mc *MetricsCollector) Start(ctx context.Context) {
	ticker := time.NewTicker(mc.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-mc.stopCh:
				return
			case <-ticker.C:
				mc.sample()
			}
		}
	}()
}

// Stop terminates the metrics collector.
func (mc *MetricsCollector) Stop() {
	mc.closeOnce.Do(func() {
		close(mc.stopCh)
	})
}

// GetMetrics returns the latest cached SystemMetrics snapshot.
func (mc *MetricsCollector) GetMetrics() *SystemMetrics {
	if mc == nil {
		return nil
	}
	m := mc.cached.Load()
	if m == nil {
		metrics, _ := collectPlatformMetrics(nil)
		return metrics
	}
	return m
}

func (mc *MetricsCollector) sample() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	metrics, raw := collectPlatformMetrics(mc.prevRaw)
	if metrics != nil {
		mc.cached.Store(metrics)
		mc.prevRaw = raw
	}
}

// FormatUptime turns seconds into "Xd Yh Zm"
func FormatUptime(seconds uint64) string {
	d := seconds / 86400
	h := (seconds % 86400) / 3600
	m := (seconds % 3600) / 60
	return fmt.Sprintf("%dd %dh %dm", d, h, m)
}
