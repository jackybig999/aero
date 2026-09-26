// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"expvar"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// ServerMetrics 基于 Go 标准库 expvar 的零外部依赖指标观测中心 (Rule Phase 4.3 & L10)
type ServerMetrics struct {
	ActiveConns   *expvar.Int
	ActiveStreams *expvar.Int
	BytesSent     *expvar.Int
	BytesRecv     *expvar.Int
	SSRFBlocks    *expvar.Int
	QUICStreams   *expvar.Int
	MasqueStreams *expvar.Int
	server        *http.Server
	mu            sync.Mutex
}

var (
	metricsInitOnce sync.Once
	globalMetrics   *ServerMetrics
)

// GetGlobalMetrics 获取全局指标单例
func GetGlobalMetrics() *ServerMetrics {
	metricsInitOnce.Do(func() {
		m := &ServerMetrics{}
		m.ActiveConns = expvar.NewInt("aero_active_conns")
		m.ActiveStreams = expvar.NewInt("aero_active_streams")
		m.BytesSent = expvar.NewInt("aero_bytes_sent_total")
		m.BytesRecv = expvar.NewInt("aero_bytes_recv_total")
		m.SSRFBlocks = expvar.NewInt("aero_ssrf_blocks_total")
		m.QUICStreams = expvar.NewInt("aero_quic_streams_total")
		m.MasqueStreams = expvar.NewInt("aero_masque_streams_total")
		globalMetrics = m
	})
	return globalMetrics
}

// StartMetricsServer 启动指标暴露服务；强制绑定 127.0.0.1 隔离，外网绝对不可达 (Rule L10)
func StartMetricsServer(port int) (*ServerMetrics, error) {
	m := GetGlobalMetrics()

	if port <= 0 {
		port = 9091
	}
	bindAddr := fmt.Sprintf("127.0.0.1:%d", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// 严密二次核验：仅允许来自 127.0.0.1 或 ::1 的环回访问
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}
		remoteIP := net.ParseIP(strings.TrimSpace(remoteHost))
		if remoteIP == nil || !remoteIP.IsLoopback() {
			http.Error(w, "Forbidden: metrics endpoint strictly restricted to loopback (127.0.0.1)", http.StatusForbidden)
			return
		}
		expvar.Handler().ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:    bindAddr,
		Handler: mux,
	}

	m.mu.Lock()
	m.server = srv
	m.mu.Unlock()

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("metrics listen %s failed: %w", bindAddr, err)
	}

	go func() {
		_ = srv.Serve(ln)
	}()

	return m, nil
}

// Stop 优雅停止指标服务器
func (m *ServerMetrics) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server != nil {
		_ = m.server.Close()
	}
}
