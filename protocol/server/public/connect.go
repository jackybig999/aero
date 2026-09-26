// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aero-protocol/aero-edge/public/internal/traffic"
	protocol "github.com/aero-protocol/proto"
)

// handleConnect：drain → 限流 → 鉴权 → 并发槽 → 拨号闸门 → 握手 → 中继
func (h *edgeHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	if h.draining.Load() {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}

	ip := traffic.ClientIP(r)
	if h.rateLimit != nil && !h.rateLimit.Allow(ip) {
		h.metrics.RateReject()
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	authHeader := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		h.failAuth(ip)
		if h.strictCamouflage {
			h.serveCamouflage(w, r)
			return
		}
		http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
		return
	}
	tok := strings.TrimPrefix(authHeader, "Bearer ")
	if !h.validator.Validate(tok) {
		h.failAuth(ip)
		if h.strictCamouflage {
			h.serveCamouflage(w, r)
			return
		}
		http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
		return
	}

	if h.connLimit != nil && !h.connLimit.TryAcquire(tok) {
		h.metrics.CapacityReject()
		if !h.quiet {
			log.Printf("[CONNECT] capacity ip=%s active=%d", ip, h.connLimit.Active())
		}
		http.Error(w, "capacity full", http.StatusServiceUnavailable)
		return
	}
	released := false
	release := func() {
		if !released && h.connLimit != nil {
			released = true
			h.connLimit.Release(tok)
		}
	}
	defer release()

	h.metrics.ConnectionStarted()
	defer h.metrics.ConnectionEnded()

	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}
	// SSRF / proxy-loop guard: never dial loopback/private from edge CONNECT
	if blocked, why := traffic.IsBlockedTarget(target); blocked {
		h.metrics.DialFailure()
		if !h.quiet {
			log.Printf("[CONNECT] blocked target %s (%s) from %s", target, why, r.RemoteAddr)
		}
		http.Error(w, "forbidden target", http.StatusForbidden)
		return
	}
	streamType := detectStreamType(target)
	if !h.quiet {
		log.Printf("[CONNECT] %s -> %s", r.RemoteAddr, target)
	}

	// HTTP 200 first so the H2 CONNECT stream is established; then handshake
	// tells us TCP vs UDP. Dialing TCP before handshake made QUIC/UDP impossible.
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	var req protocol.ConnectRequest
	if err := protocol.ReadMessage(r.Body, &req); err != nil {
		_ = protocol.WriteMessage(w, &protocol.ConnectResponse{Accepted: false, Message: "read failed"})
		return
	}
	if req.Token != "" && req.Token != tok {
		_ = protocol.WriteMessage(w, &protocol.ConnectResponse{Accepted: false, Message: "token mismatch"})
		return
	}
	if req.Token == "" {
		req.Token = tok
	}
	if !h.validator.ValidateFull(req.Token, req.Timestamp, req.Nonce) {
		h.failAuth(ip)
		_ = protocol.WriteMessage(w, &protocol.ConnectResponse{Accepted: false, Message: "invalid token or replay"})
		return
	}

	streamID := uint32(1)
	if len(req.GetStreams()) > 0 {
		s0 := req.GetStreams()[0]
		streamID = s0.GetStreamId()
		if s0.GetStreamType() != protocol.StreamType_GENERAL {
			streamType = s0.GetStreamType()
		}
		if s0.GetTargetHost() != "" && s0.GetTargetPort() != 0 {
			target = net.JoinHostPort(s0.GetTargetHost(), fmt.Sprintf("%d", s0.GetTargetPort()))
			if blocked, why := traffic.IsBlockedTarget(target); blocked {
				h.metrics.DialFailure()
				if !h.quiet {
					log.Printf("[CONNECT] blocked modified target %s (%s) from %s", target, why, r.RemoteAddr)
				}
				_ = protocol.WriteMessage(w, &protocol.ConnectResponse{Accepted: false, Message: "forbidden target"})
				return
			}
		}
	}

	var targetConn net.Conn
	var err error
	if streamType != protocol.StreamType_UDP {
		if h.dialGuard != nil {
			targetConn, err = h.dialGuard.DialTimeout("tcp", target, 10*time.Second)
		} else {
			targetConn, err = net.DialTimeout("tcp", target, 10*time.Second)
		}
		if err != nil {
			h.metrics.DialFailure()
			log.Printf("[CONNECT] dial %s: %v", target, err)
			_ = protocol.WriteMessage(w, &protocol.ConnectResponse{
				Accepted: false,
				Message:  "dial failed: " + err.Error(),
			})
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}
		applyStreamQoS(targetConn, streamType)
	}

	resp := &protocol.ConnectResponse{
		Accepted:            true,
		SessionId:           generateSessionID(),
		HeartbeatInterval:   30,
		RecommendedProtocol: "quic",
		RecommendedPort:     443,
	}
	if err := protocol.WriteMessage(w, resp); err != nil {
		if targetConn != nil {
			targetConn.Close()
		}
		return
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	sf := newSafeFlusher(w)
	params := connectRelayParams{
		Body: r.Body, SF: sf, TargetAddr: target, Target: targetConn,
		Remote: r.RemoteAddr, StreamID: streamID, StreamType: streamType,
		Req: &req, Resp: resp, Token: tok, onDone: release,
	}

	if streamType == protocol.StreamType_UDP {
		if !h.quiet {
			log.Printf("[CONNECT] UDP relay %s", target)
		}
		h.runUDPRelay(params)
		released = true
		return
	}

	h.runConnectRelay(params)
	released = true
}

func (h *edgeHandler) failAuth(ip string) {
	h.metrics.AuthFailure()
	if h.rateLimit != nil {
		h.rateLimit.RecordFail(ip)
	}
}

// serveCamouflage 优先交由 cover 伪装站点处理；若未配置 cover，则由内建标准 Nginx 欢迎页兜底，绝对不暴露 407 代理指纹
func (h *edgeHandler) serveCamouflage(w http.ResponseWriter, r *http.Request) {
	if h.cover != nil {
		h.cover.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx/1.24.0")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>html{color-scheme:light dark;}body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p><em>Thank you for using nginx.</em></p></body></html>`))
}

type connectRelayParams struct {
	Body       io.Reader
	SF         *safeFlusher
	Target     net.Conn
	TargetAddr string
	Remote     string
	StreamID   uint32
	StreamType protocol.StreamType
	Req        *protocol.ConnectRequest
	Resp       *protocol.ConnectResponse
	Token      string
	onDone     func()
}
