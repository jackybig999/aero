// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package metrics 提供服务端运行时指标收集和健康检查，支持 Prometheus 文本格式暴露。
package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Registry 保存所有运行时指标
type Registry struct {
	activeConnections  atomic.Int64
	totalConnections   atomic.Uint64
	bytesSent          atomic.Uint64
	bytesReceived      atomic.Uint64
	authFailures       atomic.Uint64
	dialFailures       atomic.Uint64
	heartbeatTimeouts  atomic.Uint64
	capacityRejects    atomic.Uint64
	rateRejects        atomic.Uint64
	idleTimeouts       atomic.Uint64

	startTime time.Time
	mu        sync.RWMutex
	alerts    []Alert
}

// Alert 表示一条告警记录
type Alert struct {
	Name      string    `json:"name"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// Thresholds 告警阈值配置
type Thresholds struct {
	MaxActiveConnections int64
	MaxAuthFailureRate   float64 // 最近一分钟认证失败率
	MaxDialFailureRate   float64 // 最近一分钟目标连接失败率
}

// DefaultThresholds 返回默认告警阈值
func DefaultThresholds() Thresholds {
	return Thresholds{
		MaxActiveConnections: 10000,
		MaxAuthFailureRate:   0.3,
		MaxDialFailureRate:   0.2,
	}
}

// NewRegistry 创建指标注册表
func NewRegistry() *Registry {
	return &Registry{
		startTime: time.Now().UTC(),
		alerts:    make([]Alert, 0),
	}
}

// ConnectionStarted 记录新连接开始
func (r *Registry) ConnectionStarted() {
	r.activeConnections.Add(1)
	r.totalConnections.Add(1)
}

// ConnectionEnded 记录连接结束
func (r *Registry) ConnectionEnded() {
	r.activeConnections.Add(-1)
}

// AddBytesSent 累加发送字节数
func (r *Registry) AddBytesSent(n uint64) {
	r.bytesSent.Add(n)
}

// AddBytesReceived 累加接收字节数
func (r *Registry) AddBytesReceived(n uint64) {
	r.bytesReceived.Add(n)
}

// AuthFailure 记录认证失败
func (r *Registry) AuthFailure() {
	r.authFailures.Add(1)
}

// DialFailure 记录目标连接失败
func (r *Registry) DialFailure() {
	r.dialFailures.Add(1)
}

// HeartbeatTimeout 记录心跳超时
func (r *Registry) HeartbeatTimeout() {
	r.heartbeatTimeouts.Add(1)
}

// CapacityReject 并发槽满拒绝
func (r *Registry) CapacityReject() { r.capacityRejects.Add(1) }

// RateReject IP 限速拒绝
func (r *Registry) RateReject() { r.rateRejects.Add(1) }

// IdleTimeout 空闲超时断开
func (r *Registry) IdleTimeout() { r.idleTimeouts.Add(1) }

// Snapshot 返回当前指标快照
func (r *Registry) Snapshot() Snapshot {
	return Snapshot{
		ActiveConnections: r.activeConnections.Load(),
		TotalConnections:  r.totalConnections.Load(),
		BytesSent:         r.bytesSent.Load(),
		BytesReceived:     r.bytesReceived.Load(),
		AuthFailures:      r.authFailures.Load(),
		DialFailures:      r.dialFailures.Load(),
		HeartbeatTimeouts: r.heartbeatTimeouts.Load(),
		CapacityRejects:   r.capacityRejects.Load(),
		RateRejects:       r.rateRejects.Load(),
		IdleTimeouts:      r.idleTimeouts.Load(),
		UptimeSeconds:     time.Since(r.startTime).Seconds(),
		Timestamp:         time.Now().UTC(),
	}
}

// Snapshot 指标快照
type Snapshot struct {
	ActiveConnections  int64     `json:"active_connections"`
	TotalConnections   uint64    `json:"total_connections"`
	BytesSent          uint64    `json:"bytes_sent"`
	BytesReceived      uint64    `json:"bytes_received"`
	AuthFailures       uint64    `json:"auth_failures"`
	DialFailures       uint64    `json:"dial_failures"`
	HeartbeatTimeouts  uint64    `json:"heartbeat_timeouts"`
	CapacityRejects    uint64    `json:"capacity_rejects"`
	RateRejects        uint64    `json:"rate_rejects"`
	IdleTimeouts       uint64    `json:"idle_timeouts"`
	UptimeSeconds      float64   `json:"uptime_seconds"`
	Timestamp          time.Time `json:"timestamp"`
}

// Prometheus 输出 Prometheus 文本格式指标
func (s Snapshot) Prometheus() string {
	out := "# HELP aero_edge_active_connections Current active CONNECT tunnels\n"
	out += "# TYPE aero_edge_active_connections gauge\n"
	out += fmt.Sprintf("aero_edge_active_connections %d\n", s.ActiveConnections)

	out += "# HELP aero_edge_total_connections_total Total CONNECT tunnels accepted\n"
	out += "# TYPE aero_edge_total_connections_total counter\n"
	out += fmt.Sprintf("aero_edge_total_connections_total %d\n", s.TotalConnections)

	out += "# HELP aero_edge_bytes_sent_total Total bytes sent to clients\n"
	out += "# TYPE aero_edge_bytes_sent_total counter\n"
	out += fmt.Sprintf("aero_edge_bytes_sent_total %d\n", s.BytesSent)

	out += "# HELP aero_edge_bytes_received_total Total bytes received from clients\n"
	out += "# TYPE aero_edge_bytes_received_total counter\n"
	out += fmt.Sprintf("aero_edge_bytes_received_total %d\n", s.BytesReceived)

	out += "# HELP aero_edge_auth_failures_total Total authentication failures\n"
	out += "# TYPE aero_edge_auth_failures_total counter\n"
	out += fmt.Sprintf("aero_edge_auth_failures_total %d\n", s.AuthFailures)

	out += "# HELP aero_edge_dial_failures_total Total target dial failures\n"
	out += "# TYPE aero_edge_dial_failures_total counter\n"
	out += fmt.Sprintf("aero_edge_dial_failures_total %d\n", s.DialFailures)

	out += "# HELP aero_edge_heartbeat_timeouts_total Total heartbeat timeouts\n"
	out += "# TYPE aero_edge_heartbeat_timeouts_total counter\n"
	out += fmt.Sprintf("aero_edge_heartbeat_timeouts_total %d\n", s.HeartbeatTimeouts)

	out += "# HELP aero_edge_capacity_rejects_total Concurrent capacity rejections\n"
	out += "# TYPE aero_edge_capacity_rejects_total counter\n"
	out += fmt.Sprintf("aero_edge_capacity_rejects_total %d\n", s.CapacityRejects)

	out += "# HELP aero_edge_rate_rejects_total IP rate limit rejections\n"
	out += "# TYPE aero_edge_rate_rejects_total counter\n"
	out += fmt.Sprintf("aero_edge_rate_rejects_total %d\n", s.RateRejects)

	out += "# HELP aero_edge_idle_timeouts_total Idle tunnel timeouts\n"
	out += "# TYPE aero_edge_idle_timeouts_total counter\n"
	out += fmt.Sprintf("aero_edge_idle_timeouts_total %d\n", s.IdleTimeouts)

	out += "# HELP aero_edge_uptime_seconds Server uptime in seconds\n"
	out += "# TYPE aero_edge_uptime_seconds gauge\n"
	out += fmt.Sprintf("aero_edge_uptime_seconds %.3f\n", s.UptimeSeconds)

	return out
}

// HealthStatus 健康状态
type HealthStatus struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// HealthHandler 返回 /health 的 HTTP handler
func (r *Registry) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		status := HealthStatus{Status: "healthy", Timestamp: time.Now().UTC()}
		fmt.Fprintf(w, `{"status":"%s","timestamp":"%s"}`, status.Status, status.Timestamp.Format(time.RFC3339))
	}
}

// MetricsHandler 返回 /metrics 的 HTTP handler
func (r *Registry) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(r.Snapshot().Prometheus()))
	}
}

// RecordAlert 记录一条告警
func (r *Registry) RecordAlert(severity, name, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, Alert{
		Name:      name,
		Severity:  severity,
		Message:   message,
		Timestamp: time.Now().UTC(),
	})
	// 保留最近 100 条
	if len(r.alerts) > 100 {
		r.alerts = r.alerts[len(r.alerts)-100:]
	}
}

// RecentAlerts 返回最近的告警记录
func (r *Registry) RecentAlerts(limit int) []Alert {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > len(r.alerts) {
		limit = len(r.alerts)
	}
	start := len(r.alerts) - limit
	if start < 0 {
		start = 0
	}
	result := make([]Alert, limit)
	copy(result, r.alerts[start:])
	return result
}

// CheckThresholds 根据当前指标和阈值生成告警
func (r *Registry) CheckThresholds(t Thresholds) []Alert {
	var alerts []Alert
	snap := r.Snapshot()

	if t.MaxActiveConnections > 0 && snap.ActiveConnections > t.MaxActiveConnections {
		alerts = append(alerts, Alert{
			Name:      "HighActiveConnections",
			Severity:  "warning",
			Message:   fmt.Sprintf("active connections %d exceeds threshold %d", snap.ActiveConnections, t.MaxActiveConnections),
			Timestamp: time.Now().UTC(),
		})
	}

	total := snap.TotalConnections
	if total > 0 {
		authRate := float64(snap.AuthFailures) / float64(total)
		if t.MaxAuthFailureRate > 0 && authRate > t.MaxAuthFailureRate {
			alerts = append(alerts, Alert{
				Name:      "HighAuthFailureRate",
				Severity:  "critical",
				Message:   fmt.Sprintf("auth failure rate %.2f exceeds threshold %.2f", authRate, t.MaxAuthFailureRate),
				Timestamp: time.Now().UTC(),
			})
		}
		dialRate := float64(snap.DialFailures) / float64(total)
		if t.MaxDialFailureRate > 0 && dialRate > t.MaxDialFailureRate {
			alerts = append(alerts, Alert{
				Name:      "HighDialFailureRate",
				Severity:  "warning",
				Message:   fmt.Sprintf("dial failure rate %.2f exceeds threshold %.2f", dialRate, t.MaxDialFailureRate),
				Timestamp: time.Now().UTC(),
			})
		}
	}

	return alerts
}

