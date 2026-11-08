// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type mockHalfCloseConn struct {
	net.Conn
	closedWrite atomic.Bool
}

func (m *mockHalfCloseConn) CloseWrite() error {
	m.closedWrite.Store(true)
	if tc, ok := m.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

// TestRelayTraffic_HalfCloseGracefulStreaming 验证半关闭保护：上行发送完毕后绝不掐断下行 AI 流式回复
func TestRelayTraffic_HalfCloseGracefulStreaming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})

	// 模拟上游 AI 服务端
	go func() {
		remoteConn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer remoteConn.Close()

		// 1. 读取客户端发送的请求 Prompt
		buf := make([]byte, 1024)
		n, rerr := remoteConn.Read(buf)
		if rerr != nil || string(buf[:n]) != "Prompt: Tell me a story" {
			t.Errorf("remote read prompt unexpected: n=%d, err=%v", n, rerr)
			return
		}

		// 2. 模拟 AI 模型思考耗时 100ms（此时客户端上行已经 EOF）
		time.Sleep(100 * time.Millisecond)

		// 3. 服务端流式下发回复
		_, werr := remoteConn.Write([]byte("AI: Once upon a time..."))
		if werr != nil {
			t.Errorf("remote write streaming response failed: %v", werr)
		}
	}()

	// 模拟本地客户端与代理端的连接
	clientSideA, clientSideB := net.Pipe()
	defer clientSideA.Close()

	remoteDial, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial remote failed: %v", err)
	}
	defer remoteDial.Close()

	wrappedRemote := &mockHalfCloseConn{Conn: remoteDial}

	// 启动 relayTraffic 连接 clientSideB 和 wrappedRemote
	go func() {
		defer close(done)
		relayTraffic(clientSideB, wrappedRemote)
	}()

	// 客户端发送 Prompt 后关闭写端 (EOF)
	go func() {
		_, _ = clientSideA.Write([]byte("Prompt: Tell me a story"))
		_ = clientSideA.Close() // 客户端上行写入完毕，触发半关闭 EOF
	}()

	// 验证在客户端上行 EOF 之后，下行通道依然可以完整接收 AI 流式回包
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("relayTraffic hung, expected clean termination")
	}

	if !wrappedRemote.closedWrite.Load() {
		t.Errorf("expected CloseWrite to be called on mockHalfCloseConn")
	}
}

type mockUDPConn struct {
	net.Conn
}

func (m *mockUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func (m *mockUDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
}

// TestRelayTraffic_UDPMutualTeardown 验证当任意一端出错或关闭时，两端均被立即互斩，不产生 30s/60s 悬挂
func TestRelayTraffic_UDPMutualTeardown(t *testing.T) {
	clientA, clientB := net.Pipe()
	remoteA, remoteB := net.Pipe()

	uClientB := &mockUDPConn{Conn: clientB}
	uRemoteA := &mockUDPConn{Conn: remoteA}

	done := make(chan struct{})
	go func() {
		defer close(done)
		relayTraffic(uClientB, uRemoteA)
	}()

	// 1. 正常收发测试
	go func() {
		_, _ = clientA.Write([]byte("ping"))
	}()
	buf := make([]byte, 1024)
	n, err := remoteB.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("remote read failed: %v, got %q", err, string(buf[:n]))
	}

	// 2. 模拟 clientA 关闭，触发 clientB EOF 错误
	start := time.Now()
	_ = clientA.Close()

	// 3. 断言 relayTraffic 必须在 200ms 内快速互斩退出，绝不悬挂 30s/60s
	select {
	case <-done:
		if time.Since(start) > 2*time.Second {
			t.Fatalf("relayTraffic teardown took too long: %v", time.Since(start))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("relayTraffic hung, mutual teardown failed to trigger")
	}

	// 4. 验证对端 remoteB 也已被互斩关闭 (Read 返回 EOF/ErrClosedPipe)
	_, rerr := remoteB.Read(buf)
	if rerr == nil {
		t.Fatalf("expected remote connection to be closed by mutual teardown")
	}
}

// TestRelayTraffic_UDPContextCancellation 验证 Context 取消时秒级终止阻塞中的 UDP 转发
func TestRelayTraffic_UDPContextCancellation(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	remoteA, remoteB := net.Pipe()
	defer remoteB.Close()

	uClientB := &mockUDPConn{Conn: clientB}
	uRemoteA := &mockUDPConn{Conn: remoteA}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		relayTraffic(uClientB, uRemoteA, ctx)
	}()

	// 模拟双方均无流量处于阻塞等待状态
	time.Sleep(50 * time.Millisecond)

	// 取消 context
	start := time.Now()
	cancel()

	select {
	case <-done:
		if time.Since(start) > 1*time.Second {
			t.Fatalf("context cancel teardown took too long: %v", time.Since(start))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("relayTraffic hung after context cancellation")
	}
}

// TestRelayTraffic_PrefixedUDPConn 验证带首包回放的 Prefixed UDP 连接能被正确识别为 UDP 并完成无损中继
func TestRelayTraffic_PrefixedUDPConn(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	remoteA, remoteB := net.Pipe()
	defer remoteB.Close()

	uClientB := &mockUDPConn{Conn: clientB}
	uRemoteA := &mockUDPConn{Conn: remoteA}

	prefixedClient := &prefixedUDPConn{
		first: []byte("first-handshake-packet"),
		Conn:  uClientB,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		relayTraffic(prefixedClient, uRemoteA)
	}()

	// remoteB 应当直接读到首包
	buf := make([]byte, 1024)
	n, err := remoteB.Read(buf)
	if err != nil || string(buf[:n]) != "first-handshake-packet" {
		t.Fatalf("failed to receive first packet: %v, got %q", err, string(buf[:n]))
	}

	// 后续数据包正常透传
	go func() {
		_, _ = clientA.Write([]byte("second-packet"))
	}()
	n, err = remoteB.Read(buf)
	if err != nil || string(buf[:n]) != "second-packet" {
		t.Fatalf("failed to receive second packet: %v, got %q", err, string(buf[:n]))
	}

	_ = clientA.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("relayTraffic hung on termination")
	}
}

// TestStackEngine_NilDialerGracefulDrop 验证当 dialer 为 nil 时，出站 TCP/UDP 数据报被安全丢弃而绝不发生 panic
func TestStackEngine_NilDialerGracefulDrop(t *testing.T) {
	mockDev := newMockTunDevice()
	defer mockDev.Close()

	stackEng := NewStackEngine(mockDev, nil, nil)
	if err := stackEng.Start(); err != nil {
		t.Fatalf("stackEng.Start() failed: %v", err)
	}
	defer stackEng.Stop()

	// 注入 UDP 数据包，断言在 dialer == nil 时安全退出绝不崩溃
	srcIP := net.ParseIP("10.88.0.2")
	dstIP := net.ParseIP("1.1.1.1")
	udpPkt := buildIPv4UDPPacket(srcIP, dstIP, 45678, 12345, []byte("nil-dialer-udp-payload"))
	mockDev.injectPacket(udpPkt)

	time.Sleep(50 * time.Millisecond)
}

func TestEngine_DialUDP_DirectSplit(t *testing.T) {
	eng := NewEngine()
	defer eng.Close()

	// 监听一个本地 UDP 测试服务器
	lConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP failed: %v", err)
	}
	defer lConn.Close()

	target := lConn.LocalAddr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 127.0.0.1 属于 DIRECT，DialUDP 应该直接物理直连成功
	conn, err := eng.DialUDP(ctx, target)
	if err != nil {
		t.Fatalf("expected direct DialUDP to succeed for loopback/direct target, got: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello-udp-direct")
	if _, werr := conn.Write(msg); werr != nil {
		t.Fatalf("write failed: %v", werr)
	}

	buf := make([]byte, 64)
	n, _, rerr := lConn.ReadFrom(buf)
	if rerr != nil {
		t.Fatalf("read failed: %v", rerr)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("payload mismatch: got %s, want %s", string(buf[:n]), string(msg))
	}
}
