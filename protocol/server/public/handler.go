// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aero-protocol/aero-edge/public/internal/auth"
	"github.com/aero-protocol/aero-edge/public/internal/contextstore"
	"github.com/aero-protocol/aero-edge/public/internal/cover"
	"github.com/aero-protocol/aero-edge/public/internal/metrics"
	"github.com/aero-protocol/aero-edge/public/internal/subscribe"
	"github.com/aero-protocol/aero-edge/public/internal/traffic"
	"github.com/aero-protocol/aero-edge/public/internal/transport"
)

// edgeHandler 路由：ACME → CONNECT → /admin → /sub → 本机运维 → Cover
type edgeHandler struct {
	validator        *auth.Validator
	echMgr           *transport.ECHManager
	acmeHandler      http.Handler
	contextStore     contextstore.Backend
	metrics          *metrics.Registry
	subHandler       *subscribe.Handler
	cover            *cover.Site
	connLimit        *traffic.ConnLimiter
	rateLimit        *traffic.RateLimiter
	bwLimit          *traffic.BandwidthLimiter
	dialGuard        *traffic.DialGuard
	tokenStore       *auth.TokenStore
	certMgr          *transport.CertManager
	acmeWebRoot      string
	adminKey         string
	idleTimeout      time.Duration
	maxLife          time.Duration
	quiet            bool
	strictCamouflage bool
	draining         atomic.Bool
	startedAt        time.Time
}

// HandlerOptions 组装依赖
type HandlerOptions struct {
	Validator        *auth.Validator
	ECH              *transport.ECHManager
	ACME             http.Handler
	Metrics          *metrics.Registry
	ContextStore     contextstore.Backend
	SubStore         *subscribe.Store
	Cover            *cover.Site
	ConnLimit        *traffic.ConnLimiter
	RateLimit        *traffic.RateLimiter
	BWLimit          *traffic.BandwidthLimiter
	DialGuard        *traffic.DialGuard
	TokenStore       *auth.TokenStore
	CertMgr          *transport.CertManager
	ACMEWebRoot      string
	AdminKey         string
	IdleTimeout      time.Duration
	MaxLife          time.Duration
	Quiet            bool
	StrictCamouflage bool
}

// NewEdgeHandler 创建 handler
func NewEdgeHandler(opt HandlerOptions) *edgeHandler {
	reg := opt.Metrics
	if reg == nil {
		reg = metrics.NewRegistry()
	}
	coverSite := opt.Cover
	if coverSite == nil {
		coverSite = cover.New(cover.Config{})
	}
	ctxStore := opt.ContextStore
	if ctxStore == nil {
		ctxStore = contextstore.NewMemory(4096)
	}
	idle := opt.IdleTimeout
	if idle <= 0 {
		idle = 15 * time.Minute
	}
	h := &edgeHandler{
		validator:        opt.Validator,
		echMgr:           opt.ECH,
		acmeHandler:      opt.ACME,
		contextStore:     ctxStore,
		metrics:          reg,
		cover:            coverSite,
		connLimit:        opt.ConnLimit,
		rateLimit:        opt.RateLimit,
		bwLimit:          opt.BWLimit,
		dialGuard:        opt.DialGuard,
		tokenStore:       opt.TokenStore,
		certMgr:          opt.CertMgr,
		acmeWebRoot:      strings.TrimSpace(opt.ACMEWebRoot),
		adminKey:         opt.AdminKey,
		idleTimeout:      idle,
		maxLife:          opt.MaxLife,
		quiet:            opt.Quiet,
		strictCamouflage: opt.StrictCamouflage,
		startedAt:        time.Now(),
	}
	if opt.SubStore != nil {
		h.subHandler = &subscribe.Handler{Store: opt.SubStore}
	}
	return h
}

// SetDraining 优雅退出：拒绝新 CONNECT
func (h *edgeHandler) SetDraining(v bool) { h.draining.Store(v) }

type safeFlusher struct {
	w     io.Writer
	flush func()
	mu    sync.Mutex
}

func newSafeFlusher(w http.ResponseWriter) *safeFlusher {
	f, _ := w.(http.Flusher)
	return &safeFlusher{
		w: w,
		flush: func() {
			if f != nil {
				f.Flush()
			}
		},
	}
}

func (sf *safeFlusher) Write(p []byte) (int, error) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	return sf.w.Write(p)
}

func (sf *safeFlusher) Flush() {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.flush()
}

// ServeHTTP 路由
func (h *edgeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		if h.acmeHandler != nil {
			h.acmeHandler.ServeHTTP(w, r)
			return
		}
		if h.acmeWebRoot != "" {
			h.serveACMEWebRoot(w, r)
			return
		}
	}
	if r.Method == http.MethodConnect {
		// Plain :80 is for ACME/webroot, not plaintext CONNECT.
		if r.TLS == nil && h.acmeWebRoot != "" {
			http.NotFound(w, r)
			return
		}
		h.handleConnect(w, r)
		return
	}
	if h.tryAdmin(w, r) {
		return
	}
	if h.subHandler != nil && strings.HasPrefix(r.URL.Path, "/sub/") {
		if h.rateLimit != nil {
			ip := traffic.ClientIP(r)
			if !h.rateLimit.Allow("sub:" + ip) {
				h.metrics.RateReject()
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		if h.subHandler.TryServe(w, r) {
			return
		}
	}
	if cover.IsLoopback(r) {
		switch r.URL.Path {
		case "/health":
			h.metrics.HealthHandler()(w, r)
			return
		case "/metrics":
			h.metrics.MetricsHandler()(w, r)
		case "/ech-config":
			if h.echMgr != nil {
				h.echMgr.Handler(w, r)
			} else {
				http.Error(w, "ECH not configured", http.StatusServiceUnavailable)
			}
			return
		}
	}
	if h.cover != nil {
		h.cover.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

// serveACMEWebRoot serves a single token file from the webroot. No path traversal.
func (h *edgeHandler) serveACMEWebRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := path.Base(strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/"))
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(h.acmeWebRoot, name))
}
