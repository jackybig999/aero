// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package api provides localhost JSON API for GUI/CLI control.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server HTTP API 服务器
type Server struct {
	addr      string
	state     *AppState
	mu        sync.RWMutex
	srv       *http.Server
	runtime   Runtime
	ui        fs.FS
	ctrlToken string
}

// AppState 应用运行状态（由 main 协程更新，API 读取）
// Client Control API v1 — GUI / Desktop / 未来 iOS 共用字段。
type AppState struct {
	Connected   bool            `json:"connected"`
	Mode        string          `json:"mode"`                   // socks | sysproxy | tun
	Listen      string          `json:"listen"`                 // SOCKS5 127.0.0.1:55555
	HTTPListen  string          `json:"http_listen,omitempty"`  // HTTP CONNECT 127.0.0.1:55556
	SubURL      string          `json:"sub_url,omitempty"`      // may be full URL for UI QR
	SubURLMask  string          `json:"sub_url_mask,omitempty"` // masked for display lists
	LastError   string          `json:"last_error,omitempty"`
	Node        string          `json:"node"`
	Protocol    string          `json:"protocol"`
	RTTMs       uint32          `json:"rtt_ms"`
	UptimeStart time.Time       `json:"-"`
	UptimeSec   int64           `json:"uptime_sec"`
	BytesSent   uint64          `json:"bytes_sent"`
	BytesRecv   uint64          `json:"bytes_recv"`
	FTLAvgMs    uint64          `json:"ftl_avg_ms"`
	JitterMs    uint32          `json:"jitter_ms"`
	LossRate    float64         `json:"loss_rate"`
	StreamCount int             `json:"stream_count"`
	SplitRules  []SplitRuleInfo `json:"split_rules"`
	Nodes       []NodeInfo      `json:"nodes"`
	Version     string          `json:"version,omitempty"`
	Hint        string          `json:"hint,omitempty"` // UI tip: which apps need manual proxy
	ISP         string          `json:"isp,omitempty"`
	ISPName     string          `json:"isp_name,omitempty"`
	SNI         string          `json:"sni,omitempty"`
	// Live probe (filled by /api/v1/probe or status?probe=1)
	ProbeOK     *bool  `json:"probe_ok,omitempty"`
	ProbeMS     int64  `json:"probe_ms,omitempty"`
	ProbeDetail string `json:"probe_detail,omitempty"`
}

// SplitRuleInfo 分流规则信息
type SplitRuleInfo struct {
	Name     string   `json:"name"`
	Strategy string   `json:"strategy"`
	Domains  []string `json:"domains"`
}

// NodeInfo 节点信息
type NodeInfo struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Reachable bool   `json:"reachable"`
	RTTMs     int64  `json:"rtt_ms"`
	Active    bool   `json:"active"`
}

// SetUI serves the shared Win/macOS/iOS HTML shell at / (same files on every OS).
func (s *Server) SetUI(fsys fs.FS) {
	s.mu.Lock()
	s.ui = fsys
	s.mu.Unlock()
}

// NewServer 创建 API 服务器
func NewServer(addr string) *Server {
	if addr == "" {
		addr = "127.0.0.1:19877"
	}
	return &Server{
		addr: addr,
		state: &AppState{
			Mode:     "socks",
			Protocol: "aero/2.0",
			Version:  "aero-ech v2.0.0",
		},
	}
}

// State 返回当前状态（线程安全）
func (s *Server) State() *AppState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := *s.state
	if state.Connected && !state.UptimeStart.IsZero() {
		state.UptimeSec = int64(time.Since(state.UptimeStart).Seconds())
	}
	return &state
}

// UpdateState 更新状态（由 main 协程调用）
func (s *Server) UpdateState(fn func(*AppState)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.state)
}

// SetCtrlToken 设置本地控制面 Bearer Token 保护
func (s *Server) SetCtrlToken(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctrlToken = tok
}

// Start 启动 API 服务器（非阻塞）
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/connect", s.handleConnect)
	mux.HandleFunc("/api/v1/disconnect", s.handleDisconnect)
	mux.HandleFunc("/api/v1/mode", s.handleMode)
	mux.HandleFunc("/api/v1/nodes", s.handleNodes)
	mux.HandleFunc("/api/v1/nodes/switch", s.handleNodeSwitch)
	mux.HandleFunc("/api/v1/split/rules", s.handleSplitRules)
	mux.HandleFunc("/api/v1/qos/stats", s.handleQoSStats)
	mux.HandleFunc("/api/v1/traffic", s.handleTraffic)
	mux.HandleFunc("/api/v1/config", s.handleConfig)
	mux.HandleFunc("/api/v1/config/reload", s.handleConfigReload)
	mux.HandleFunc("/api/v1/version", s.handleVersion)
	mux.HandleFunc("/api/v1/import", s.handleImport)
	healthFn := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "service": "aero-ech-api"})
	}
	mux.HandleFunc("/health", healthFn)
	mux.HandleFunc("/api/v1/health", healthFn)
	mux.HandleFunc("/api/v1/probe", s.handleProbe)
	// PAC for system proxy — HTTP URL works better than file:// for Chrome/Edge
	mux.HandleFunc("/proxy.pac", s.handlePAC)
	mux.HandleFunc("/api/v1/proxy.pac", s.handlePAC)
	if s.ui != nil {
		mux.Handle("/", uiFileServer(s.ui))
	}

	var handler http.Handler = mux
	if s.ctrlToken != "" {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			// 白名单：健康检查、PAC、静态资源及只读状态
			if path == "/health" || path == "/api/v1/health" ||
				strings.HasSuffix(path, "/proxy.pac") ||
				path == "/favicon.ico" ||
				path == "/api/v1/status" ||
				path == "/api/v1/probe" ||
				path == "/" ||
				strings.HasPrefix(path, "/assets/") ||
				r.Method == http.MethodOptions {
				mux.ServeHTTP(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			token := ""
			if strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			}
			if token == "" {
				token = r.Header.Get("X-Ctrl-Token")
			}
			if token == "" {
				token = r.URL.Query().Get("ctrl_token")
			}
			if token == "" || subtle.ConstantTimeCompare([]byte(s.ctrlToken), []byte(token)) != 1 {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"code":  http.StatusUnauthorized,
					"error": "unauthorized: invalid or missing ctrl.token",
				})
				return
			}
			mux.ServeHTTP(w, r)
		})
	}

	s.srv = &http.Server{Handler: corsWrap(handler)}
	go func() {
		log.Printf("[API] Listening on %s", s.addr)
		if err := s.srv.Serve(ln); err != http.ErrServerClosed {
			log.Printf("[API] Server error: %v", err)
		}
	}()
	return nil
}

// Stop 停止 API 服务器
func (s *Server) Stop() {
	if s.srv != nil {
		s.srv.Close()
	}
}
