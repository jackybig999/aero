// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
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
