// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	bufPool32k = sync.Pool{
		New: func() any {
			b := make([]byte, 32*1024)
			return &b
		},
	}
	bufPool64k = sync.Pool{
		New: func() any {
			b := make([]byte, 64*1024)
			return &b
		},
	}
)

// MASQUEHandler 实现了 RFC 9298 (CONNECT-UDP) 与 RFC 9484 (CONNECT-IP) 双栈自适应握手接入
type MASQUEHandler struct {
	guard   *AuthGuard
	metrics *ServerMetrics
	mu      sync.RWMutex
	dials   map[string]net.Conn
}

// NewMASQUEHandler 创建 MASQUE 双栈处理器
func NewMASQUEHandler(guard *AuthGuard, metrics *ServerMetrics) *MASQUEHandler {
	if guard == nil {
		guard = NewAuthGuard()
	}
	if metrics == nil {
		metrics = GetGlobalMetrics()
	}
	return &MASQUEHandler{
		guard:   guard,
		metrics: metrics,
		dials:   make(map[string]net.Conn),
	}
}

// ServeHTTP 处理 HTTP/3 MASQUE 扩展握手与常规 H2 CONNECT 统一数据面分流
func (h *MASQUEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}

	target := r.RequestURI
	if target == "" {
		target = r.Host
	}

	// 1. 严格 SSRF 拦截守卫 (硬编码阻止内网与云元数据渗透)
	if err := h.guard.CheckSSRF(target); err != nil {
		h.metrics.SSRFBlocks.Add(1)
		http.Error(w, fmt.Sprintf("Forbidden: %v", err), http.StatusForbidden)
		return
	}

	// 2. 鉴权 Token 提取
	token := r.Header.Get("Proxy-Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)
	if token == "" {
		token = r.Header.Get("X-Aero-Token")
	}

	// 3. 并发槽位管控
	if token != "" && !h.guard.AcquireSlot(token) {
		http.Error(w, "Too Many Requests: per-token concurrency quota exceeded", http.StatusTooManyRequests)
		return
	}
	if token != "" {
		defer h.guard.ReleaseSlot(token)
	}

	// 4. 协议通道分发：识别是否为 MASQUE 扩展
	isMASQUE := (r.Header.Get(":protocol") == "connect-udp" || r.Header.Get("Capsule-Protocol") == "?1")
	if isMASQUE {
		h.metrics.MasqueStreams.Add(1)
		h.handleMASQUEUDP(w, r, target)
	} else {
		h.metrics.QUICStreams.Add(1)
		h.handleStandardH2CONNECT(w, r, target)
	}
}

func (h *MASQUEHandler) handleStandardH2CONNECT(w http.ResponseWriter, r *http.Request, target string) {
	// 拨号远端目标
	destConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("Dial target failed: %v", err), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	h.metrics.ActiveStreams.Add(1)
	defer h.metrics.ActiveStreams.Add(-1)

	// 双向 0-Alloc 拷贝转发
	errCh := make(chan error, 2)
	go func() {
		bp := bufPool32k.Get().(*[]byte)
		defer bufPool32k.Put(bp)
		_, err := io.CopyBuffer(destConn, r.Body, *bp)
		errCh <- err
	}()

	go func() {
		bp := bufPool32k.Get().(*[]byte)
		defer bufPool32k.Put(bp)
		_, err := io.CopyBuffer(w, destConn, *bp)
		errCh <- err
	}()

	<-errCh
	_ = destConn.Close()
	<-errCh
}

func (h *MASQUEHandler) handleMASQUEUDP(w http.ResponseWriter, r *http.Request, target string) {
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		http.Error(w, fmt.Sprintf("Resolve UDP target failed: %v", err), http.StatusBadGateway)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Dial UDP failed: %v", err), http.StatusBadGateway)
		return
	}
	defer udpConn.Close()

	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	h.metrics.ActiveStreams.Add(1)
	defer h.metrics.ActiveStreams.Add(-1)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	errCh := make(chan error, 2)

	// Client Body -> UDP target
	go func() {
		bp := bufPool64k.Get().(*[]byte)
		defer bufPool64k.Put(bp)
		buf := *bp
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := udpConn.Write(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
				h.metrics.BytesSent.Add(int64(n))
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// UDP target -> Client ResponseWriter
	go func() {
		bp := bufPool64k.Get().(*[]byte)
		defer bufPool64k.Put(bp)
		buf := *bp
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := udpConn.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				h.metrics.BytesRecv.Add(int64(n))
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-errCh:
	}
	_ = udpConn.Close()
	select {
	case <-errCh:
	case <-time.After(200 * time.Millisecond):
	}
}
