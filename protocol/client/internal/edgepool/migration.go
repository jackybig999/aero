// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package edgepool 实现网络劣化检测。
package edgepool

import (
	"sync"
	"time"
)

// Detector 劣化检测器
type Detector struct {
	mu            sync.Mutex
	rttSamples    []time.Duration
	lossCount     int
	totalCount    int
	maxSamples    int
	rttThreshold  float64 // RTT 突增阈值（倍数），默认 1.5
	lossThreshold float64 // 丢包率阈值，默认 0.05
}

// NewDetector 创建劣化检测器
func NewDetector(maxSamples int) *Detector {
	return &Detector{
		rttSamples:    make([]time.Duration, 0, maxSamples),
		maxSamples:    maxSamples,
		rttThreshold:  1.5,
		lossThreshold: 0.05,
	}
}

// RecordRTT 记录 RTT 样本
func (d *Detector) RecordRTT(rtt time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.rttSamples) >= d.maxSamples {
		d.rttSamples = d.rttSamples[1:]
	}
	d.rttSamples = append(d.rttSamples, rtt)
}

// RecordLoss 记录丢包事件
func (d *Detector) RecordLoss(lost bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.totalCount++
	if lost {
		d.lossCount++
	}
}

// ShouldSwitch 判断是否应该切换
func (d *Detector) ShouldSwitch() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.rttSamples) < 2 {
		return false, ""
	}

	var sum time.Duration
	for _, s := range d.rttSamples {
		sum += s
	}
	avg := sum / time.Duration(len(d.rttSamples))
	latest := d.rttSamples[len(d.rttSamples)-1]

	if avg > 0 && float64(latest) > float64(avg)*d.rttThreshold {
		return true, "RTT spike"
	}

	if d.totalCount >= 10 {
		lossRate := float64(d.lossCount) / float64(d.totalCount)
		if lossRate > d.lossThreshold {
			return true, "high loss rate"
		}
	}

	return false, ""
}

// Reset 重置检测器状态
func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rttSamples = d.rttSamples[:0]
	d.lossCount = 0
	d.totalCount = 0
}
