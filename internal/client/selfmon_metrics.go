// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import "runtime/metrics"

// readRuntimeMetric 读取一个 float64 的运行时指标；不存在或类型不符返回 0。
func readRuntimeMetric(name string) float64 {
	s := []metrics.Sample{{Name: name}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindFloat64 {
		return 0
	}
	return s[0].Value.Float64()
}
