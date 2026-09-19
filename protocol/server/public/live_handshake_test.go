// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	aeroproto "github.com/aero-protocol/proto"
	"github.com/aero-protocol/aero-edge/public/internal/auth"
	"github.com/aero-protocol/aero-edge/public/internal/contextstore"
	"github.com/aero-protocol/aero-edge/public/internal/metrics"
	"github.com/aero-protocol/aero-edge/public/internal/protocol"
	"github.com/aero-protocol/aero-edge/public/internal/traffic"
	"github.com/aero-protocol/aero-edge/public/internal/transport"
	"golang.org/x/net/http2"
)

func TestLiveServerHandshake(t *testing.T) {
	// 1. 设置鉴权令牌与服务端组件
	validToken := "aero-test-secret-token-2026"
	validator := auth.NewValidator()
	validator.AddToken(validToken, "test-user", 24*time.Hour)

	certMgr, err := transport.NewCertManager(transport.CertConfig{
		Source:  transport.SelfSigned,
		Domains: []string{"127.0.0.1", "localhost"},
	})
	if err != nil {
		t.Fatalf("failed to create cert manager: %v", err)
	}

	echMgr := transport.NewECHManager("cdn-aero.com")
	_, err = echMgr.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate ECH key: %v", err)
	}

	cl := traffic.NewConnLimiter(100, 20)
	rl := traffic.NewRateLimiter(500)
	bl := traffic.NewBandwidthLimiter(0)
	dg := traffic.NewDialGuard(100)
	reg := metrics.NewRegistry()
	ctxStore := contextstore.NewMemory(100)

	handler := NewEdgeHandler(HandlerOptions{
		Validator:    validator,
		ECH:          echMgr,
		Metrics:      reg,
		ContextStore: ctxStore,
		ConnLimit:    cl,
		RateLimit:    rl,
		BWLimit:      bl,
		DialGuard:    dg,
		IdleTimeout:  10 * time.Minute,
		MaxLife:      time.Hour,
		Quiet:        false,
	})

	// 2. 启动真正的 TLS + HTTP/2 服务端监听器 (随机端口)
	tlsCert := certMgr.Certificate()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen tcp: %v", err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, tlsConfig)
	defer tlsLn.Close()

	server := &http.Server{
		Handler: handler,
	}
	if err := http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams: 100,
	}); err != nil {
		t.Fatalf("failed to configure http2: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = server.Serve(tlsLn)
	}()
	defer func() {
		_ = server.Close()
		wg.Wait()
	}()

	serverAddr := ln.Addr().String()
	t.Logf("[SERVER] Started live edge server on %s", serverAddr)

	// 3. 客户端模拟真实 HTTP/2 CONNECT 握手过程
	t.Run("ValidTokenHandshakeSuccess", func(t *testing.T) {
		clientTLS := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		}
		clientConn, err := tls.Dial("tcp", serverAddr, clientTLS)
		if err != nil {
			t.Fatalf("client TLS dial failed: %v", err)
		}
		defer clientConn.Close()

		h2Transport := &http2.Transport{
			TLSClientConfig: clientTLS,
		}
		h2Conn, err := h2Transport.NewClientConn(clientConn)
		if err != nil {
			t.Fatalf("http2 NewClientConn failed: %v", err)
		}
		defer h2Conn.Close()

		// 构造 CONNECT 双向管道
		pr, pw := io.Pipe()
		req, err := http.NewRequest(http.MethodConnect, "https://example.com:443", pr)
		if err != nil {
			t.Fatalf("create CONNECT request failed: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+validToken)

		// 发起 HTTP/2 CONNECT 请求
		resp, err := h2Conn.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip CONNECT failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 from CONNECT, got %d", resp.StatusCode)
		}
		t.Logf("[HANDSHAKE] HTTP/2 CONNECT established with HTTP 200 OK")

		// 客户端向服务端写入 Protobuf ConnectRequest
		nonce := []byte("1234567890abcdef")
		connectReq := &aeroproto.ConnectRequest{
			Version:   "aero/2.0",
			Token:     validToken,
			Timestamp: uint64(time.Now().UnixMilli()),
			Nonce:     nonce,
			Streams: []*aeroproto.StreamSpec{
				{
					StreamId:   1,
					TargetHost: "example.com",
					TargetPort: 443,
					StreamType: aeroproto.StreamType_AI,
				},
			},
		}

		go func() {
			defer pw.Close()
			if err := protocol.WriteMessage(pw, connectReq); err != nil {
				t.Errorf("write ConnectRequest failed: %v", err)
			}
		}()

		// 客户端从服务端读取 Protobuf ConnectResponse
		var connectResp aeroproto.ConnectResponse
		if err := protocol.ReadMessage(resp.Body, &connectResp); err != nil {
			t.Fatalf("read ConnectResponse failed: %v", err)
		}

		if !connectResp.Accepted {
			t.Fatalf("ConnectResponse rejected: %s", connectResp.Message)
		}
		if connectResp.SessionId == "" {
			t.Fatalf("expected non-empty session ID")
		}

		t.Logf("[SUCCESS] Live Handshake verified! SessionID: %s, RecommendedProtocol: %s",
			connectResp.SessionId, connectResp.RecommendedProtocol)
	})

	// 4. 测试非法 Token 认证被正确拒绝
	t.Run("InvalidTokenRejected", func(t *testing.T) {
		clientTLS := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		}
		clientConn, err := tls.Dial("tcp", serverAddr, clientTLS)
		if err != nil {
			t.Fatalf("client TLS dial failed: %v", err)
		}
		defer clientConn.Close()

		h2Transport := &http2.Transport{
			TLSClientConfig: clientTLS,
		}
		h2Conn, err := h2Transport.NewClientConn(clientConn)
		if err != nil {
			t.Fatalf("http2 NewClientConn failed: %v", err)
		}
		defer h2Conn.Close()

		req, err := http.NewRequest(http.MethodConnect, "https://example.com:443", nil)
		if err != nil {
			t.Fatalf("create CONNECT request failed: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer invalid-token-xyz")

		resp, err := h2Conn.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("expected 407 ProxyAuthRequired for bad token, got %d", resp.StatusCode)
		}
		t.Logf("[SECURITY] Invalid token rejected correctly with 407 Proxy Authentication Required")
	})

	// 4.1 测试严格伪装模式下，未授权探测被 Cover 伪装接管（绝不泄露 407 代理指纹）
	t.Run("StrictCamouflageProbingDefense", func(t *testing.T) {
		handler.strictCamouflage = true
		defer func() { handler.strictCamouflage = false }()

		clientTLS := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		}
		clientConn, err := tls.Dial("tcp", serverAddr, clientTLS)
		if err != nil {
			t.Fatalf("client TLS dial failed: %v", err)
		}
		defer clientConn.Close()

		h2Transport := &http2.Transport{
			TLSClientConfig: clientTLS,
		}
		h2Conn, err := h2Transport.NewClientConn(clientConn)
		if err != nil {
			t.Fatalf("http2 NewClientConn failed: %v", err)
		}
		defer h2Conn.Close()

		req, err := http.NewRequest(http.MethodConnect, "https://example.com:443", nil)
		if err != nil {
			t.Fatalf("create CONNECT request failed: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer invalid-token-probe")

		resp, err := h2Conn.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusProxyAuthRequired {
			t.Fatalf("StrictCamouflage failed: server exposed 407 ProxyAuthRequired to active probe!")
		}
		t.Logf("[CAMOUFLAGE] Active probe defused! Server responded with status %d instead of 407 (anti-probing success)", resp.StatusCode)
	})

	// 5. 测试私网/环回 SSRF 防护
	t.Run("LoopbackSSRFBlocked", func(t *testing.T) {
		clientTLS := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		}
		clientConn, err := tls.Dial("tcp", serverAddr, clientTLS)
		if err != nil {
			t.Fatalf("client TLS dial failed: %v", err)
		}
		defer clientConn.Close()

		h2Transport := &http2.Transport{
			TLSClientConfig: clientTLS,
		}
		h2Conn, err := h2Transport.NewClientConn(clientConn)
		if err != nil {
			t.Fatalf("http2 NewClientConn failed: %v", err)
		}
		defer h2Conn.Close()

		req, err := http.NewRequest(http.MethodConnect, "https://127.0.0.1:22", nil)
		if err != nil {
			t.Fatalf("create CONNECT request failed: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+validToken)

		resp, err := h2Conn.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for loopback SSRF target, got %d", resp.StatusCode)
		}
		t.Logf("[SECURITY] Loopback target blocked correctly with 403 Forbidden by traffic guard")
	})
}
