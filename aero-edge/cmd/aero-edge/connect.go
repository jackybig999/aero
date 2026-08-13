// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	aeroproto "github.com/aero-protocol/proto"
	"github.com/aero-protocol/aero-edge/internal/dialguard"
	"github.com/aero-protocol/aero-edge/internal/protocol"
	"github.com/aero-protocol/aero-edge/internal/ratelimit"
)

// handleConnect：drain → 限流 → 鉴权 → 并发槽 → 拨号闸门 → 握手 → 中继
func (h *edgeHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	if h.draining.Load() {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}

	ip := ratelimit.ClientIP(r)
	if h.rateLimit != nil && !h.rateLimit.Allow(ip) {
		h.metrics.RateReject()
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	authHeader := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		h.failAuth(ip)
		http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
		return
	}
	tok := strings.TrimPrefix(authHeader, "Bearer ")
	if !h.validator.Validate(tok) {
		h.failAuth(ip)
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
	if blocked, why := dialguard.IsBlockedTarget(target); blocked {
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

	var req aeroproto.ConnectRequest
	if err := protocol.ReadMessage(r.Body, &req); err != nil {
		_ = protocol.WriteMessage(w, &aeroproto.ConnectResponse{Accepted: false, Message: "read failed"})
		return
	}
	if req.Token != "" && req.Token != tok {
		_ = protocol.WriteMessage(w, &aeroproto.ConnectResponse{Accepted: false, Message: "token mismatch"})
		return
	}
	if req.Token == "" {
		req.Token = tok
	}
	if !h.validator.ValidateFull(req.Token, req.Timestamp, req.Nonce) {
		h.failAuth(ip)
		_ = protocol.WriteMessage(w, &aeroproto.ConnectResponse{Accepted: false, Message: "invalid token or replay"})
		return
	}

	streamID := uint32(1)
	if len(req.GetStreams()) > 0 {
		s0 := req.GetStreams()[0]
		streamID = s0.GetStreamId()
		if s0.GetStreamType() != aeroproto.StreamType_GENERAL {
			streamType = s0.GetStreamType()
		}
		if s0.GetTargetHost() != "" && s0.GetTargetPort() != 0 {
			target = net.JoinHostPort(s0.GetTargetHost(), fmt.Sprintf("%d", s0.GetTargetPort()))
		}
	}

	resp := &aeroproto.ConnectResponse{
		Accepted:            true,
		SessionId:           generateSessionID(),
		HeartbeatInterval:   30,
		RecommendedProtocol: "tcp_h2",
		RecommendedPort:     443,
	}
	if err := protocol.WriteMessage(w, resp); err != nil {
		return
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	sf := newSafeFlusher(w)
	params := connectRelayParams{
		Body: r.Body, SF: sf, TargetAddr: target,
		Remote: r.RemoteAddr, StreamID: streamID, StreamType: streamType,
		Req: &req, Resp: resp, Token: tok, onDone: release,
	}

	if streamType == aeroproto.StreamType_UDP {
		if !h.quiet {
			log.Printf("[CONNECT] UDP relay %s", target)
		}
		h.runUDPRelay(params)
		released = true
		return
	}

	var targetConn net.Conn
	var err error
	if h.dialGuard != nil {
		targetConn, err = h.dialGuard.DialTimeout("tcp", target, 10*time.Second)
	} else {
		targetConn, err = net.DialTimeout("tcp", target, 10*time.Second)
	}
	if err != nil {
		h.metrics.DialFailure()
		log.Printf("[CONNECT] dial %s: %v", target, err)
		return
	}
	applyStreamQoS(targetConn, streamType)
	params.Target = targetConn
	h.runConnectRelay(params)
	released = true
}

func (h *edgeHandler) failAuth(ip string) {
	h.metrics.AuthFailure()
	if h.rateLimit != nil {
		h.rateLimit.RecordFail(ip)
	}
}

type connectRelayParams struct {
	Body       io.Reader
	SF         *safeFlusher
	Target     net.Conn
	TargetAddr string
	Remote     string
	StreamID   uint32
	StreamType aeroproto.StreamType
	Req        *aeroproto.ConnectRequest
	Resp       *aeroproto.ConnectResponse
	Token      string
	onDone     func()
}
