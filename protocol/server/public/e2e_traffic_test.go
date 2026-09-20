// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	protocol "github.com/aero-protocol/proto"
	"github.com/aero-protocol/aero-edge/public/internal/auth"
	"github.com/aero-protocol/aero-edge/public/internal/contextstore"
	"github.com/aero-protocol/aero-edge/public/internal/metrics"
	"github.com/aero-protocol/aero-edge/public/internal/traffic"
	"github.com/aero-protocol/aero-edge/public/internal/transport"
	"golang.org/x/net/http2"
)

// TestEndToEnd_FullHandshakeAndTrafficTransfer
// 深度回测：真实启动本地 Edge 服务端与客户端模拟器，执行：
// 1. TLS 握手 (ALPN=h2)
// 2. HTTP/2 CONNECT 握手 + Token 鉴权
// 3. 0-Alloc Protobuf ConnectRequest/Response 协商 (SessionID 生成)
// 4. 双向中继数据流 (向公共 Web 服务发起 HTTP 请求并完整接收响应)
func TestEndToEnd_FullHandshakeAndTrafficTransfer(t *testing.T) {
	validToken := "aero-e2e-secret-key-999"
	validator := auth.NewValidator()
	validator.AddToken(validToken, "e2e-tester", 24*time.Hour)

	certMgr, err := transport.NewCertManager(transport.CertConfig{
		Source:  transport.SelfSigned,
		Domains: []string{"127.0.0.1", "localhost"},
	})
	if err != nil {
		t.Fatalf("failed to create cert manager: %v", err)
	}

	cl := traffic.NewConnLimiter(100, 20)
	rl := traffic.NewRateLimiter(500)
	bl := traffic.NewBandwidthLimiter(0)
	dg := traffic.NewDialGuard(100)
	reg := metrics.NewRegistry()
	ctxStore := contextstore.NewMemory(100)

	handler := NewEdgeHandler(HandlerOptions{
		Validator:    validator,
		Metrics:      reg,
		ContextStore: ctxStore,
		ConnLimit:    cl,
		RateLimit:    rl,
		BWLimit:      bl,
		DialGuard:    dg,
		IdleTimeout:  5 * time.Minute,
		MaxLife:      time.Hour,
		Quiet:        false,
	})

	tlsCert := certMgr.Certificate()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, tlsConfig)
	defer tlsLn.Close()

	server := &http.Server{Handler: handler}
	if err := http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams: 100,
	}); err != nil {
		t.Fatalf("configure http2: %v", err)
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
	t.Logf("[E2E-SERVER] Edge server listening on %s (ALPN=h2)", serverAddr)

	// 1. 客户端发起 TLS 连接
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}
	clientConn, err := tls.Dial("tcp", serverAddr, clientTLS)
	if err != nil {
		t.Fatalf("client TLS dial failed: %v", err)
	}
	defer clientConn.Close()

	t1 := &http.Transport{TLSClientConfig: clientTLS}
	h2Transport, err := http2.ConfigureTransports(t1)
	if err != nil {
		t.Fatalf("ConfigureTransports failed: %v", err)
	}
	h2Conn, err := h2Transport.NewClientConn(clientConn)
	if err != nil {
		t.Fatalf("NewClientConn failed: %v", err)
	}
	defer h2Conn.Close()

	// 2. 客户端发起 CONNECT 握手
	targetHost := "example.com"
	targetPort := 80
	targetAddr := "example.com:80"

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "https://"+targetAddr, pr)
	if err != nil {
		t.Fatalf("create CONNECT req: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+validToken)

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed with status %d", resp.StatusCode)
	}
	t.Logf("[E2E-HANDSHAKE] Step 1: HTTP/2 CONNECT 200 OK established")

	// 3. 客户端写入 0-Alloc Protobuf ConnectRequest
	streamID := uint32(42)
	connectReq := &protocol.ConnectRequest{
		Version:   "aero/2.0",
		Token:     validToken,
		Timestamp: uint64(time.Now().UnixMilli()),
		Nonce:     []byte("test-nonce-123456"),
		Streams: []*protocol.StreamSpec{
			{
				StreamId:   streamID,
				TargetHost: targetHost,
				TargetPort: uint32(targetPort),
				StreamType: protocol.StreamType_GENERAL,
			},
		},
	}

	go func() {
		if err := protocol.WriteMessage(pw, connectReq); err != nil {
			t.Errorf("write ConnectRequest failed: %v", err)
		}
	}()

	// 4. 客户端读取服务端返回的 ConnectResponse
	var connectResp protocol.ConnectResponse
	if err := protocol.ReadMessage(resp.Body, &connectResp); err != nil {
		t.Fatalf("read ConnectResponse failed: %v", err)
	}
	if !connectResp.Accepted {
		t.Fatalf("AERO Handshake rejected: %s", connectResp.Message)
	}
	t.Logf("[E2E-HANDSHAKE] Step 2: AERO 2.0 Accepted! SessionID=%s, Protocol=%s, HBInterval=%d",
		connectResp.SessionId, connectResp.RecommendedProtocol, connectResp.HeartbeatInterval)

	// 5. 数据面真实流量双向透传 (HTTP GET example.com)
	httpRequest := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: AERO-E2E-Test\r\nConnection: close\r\n\r\n"
	tcpFrame := &protocol.TcpFrame{
		StreamId: streamID,
		Payload:  []byte(httpRequest),
		Sequence: 1,
	}

	// 写入请求数据帧
	if err := protocol.TypedWriteMessage(pw, protocol.MsgTypeTcpFrame, tcpFrame); err != nil {
		t.Fatalf("write TcpFrame failed: %v", err)
	}
	t.Logf("[E2E-TRAFFIC] Sent %d bytes HTTP GET via AERO tunnel", len(httpRequest))

	// 读取回传数据帧
	msgType, decoded, err := protocol.TypedReadMessage(resp.Body)
	if err != nil {
		t.Fatalf("read server response frame failed: %v", err)
	}
	if msgType != protocol.MsgTypeTcpFrame {
		t.Fatalf("expected MsgTypeTcpFrame, got msgType=%d", msgType)
	}

	respFrame, ok := decoded.(*protocol.TcpFrame)
	if !ok {
		t.Fatalf("decoded message is not *TcpFrame: %T", decoded)
	}

	payloadStr := string(respFrame.Payload)
	t.Logf("[E2E-TRAFFIC] Received %d bytes from remote origin:\n--- HEAD PREVIEW ---\n%s\n--- END ---",
		len(respFrame.Payload), truncate(payloadStr, 200))

	// 6. 核心断言验证
	if !strings.Contains(payloadStr, "HTTP/1.1 200 OK") && !strings.Contains(payloadStr, "HTTP/1.0 200 OK") {
		t.Fatalf("expected HTTP 200 OK from example.com, got: %s", payloadStr)
	}
	if !strings.Contains(payloadStr, "Example Domain") {
		t.Fatalf("expected 'Example Domain' in payload, got: %s", payloadStr)
	}

	t.Logf(">>> [E2E-SUCCESS] Full client-server handshake and traffic transfer verified perfectly! <<<")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... [truncated]"
}
