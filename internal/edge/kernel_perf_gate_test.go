// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"crypto/tls"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestKernelPerfGate_BufferPoolZeroAlloc 门禁 1: 验证隧道 64KB 缓冲池正常获取与归还
func TestKernelPerfGate_BufferPoolZeroAlloc(t *testing.T) {
	ptr := tunnelBufPool.Get().(*[]byte)
	if ptr == nil || len(*ptr) < 65535 {
		t.Fatalf("tunnelBufPool returned invalid buffer: %v", ptr)
	}
	buf := *ptr
	buf[0] = 0x45
	tunnelBufPool.Put(ptr)

	ptr2 := tunnelBufPool.Get().(*[]byte)
	if ptr2 == nil || len(*ptr2) < 65535 {
		t.Fatalf("tunnelBufPool second get invalid: %v", ptr2)
	}
	tunnelBufPool.Put(ptr2)
}

// 回归（ADR-0005）：QUIC 监听曾设置 SO_REUSEPORT，第二个实例可静默绑定同一 UDP 端口，
// 内核把报文随机分给两个进程导致 QUIC 连接损坏。同一地址第二次监听必须失败。
func TestKernelPerfGate_ExclusiveUDPBind(t *testing.T) {
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{*cert}}
	server := NewQUICServer(nil, nil, nil, nil, nil)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln1, err := StartQUIC("127.0.0.1:0", tlsCfg, server, ctx)
	if err != nil {
		t.Fatalf("first StartQUIC: %v", err)
	}
	defer ln1.Close()

	ln2, err := StartQUIC(ln1.Addr().String(), tlsCfg, server, ctx)
	if err == nil {
		_ = ln2.Close()
		t.Fatalf("second StartQUIC on %s succeeded; the UDP port must not be shared", ln1.Addr())
	}
}

// TestKernelPerfGate_HighConcurrencyDispatch 门禁 3: 模拟高并发流多线程数据分发安全性
func TestKernelPerfGate_HighConcurrencyDispatch(t *testing.T) {
	router := NewGlobalTunnelRouter()
	defer router.Close()

	destIP := netip.MustParseAddr("10.88.0.5")
	testConn := &readerTestConn{writes: make(chan []byte, 1000)}
	_, err := router.Register(GlobalTunnelBinding{
		Token: "perf-test-token",
		IPv4:  destIP,
		Conn:  testConn,
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	mockDev := &readerTestDevice{
		packets: make(chan []byte, 1000),
		closed:  make(chan struct{}),
		writes:  make(chan []byte, 1000),
	}

	reader, err := NewGlobalTunnelReader(context.Background(), mockDev, router)
	if err != nil {
		t.Fatalf("NewGlobalTunnelReader failed: %v", err)
	}
	reader.Start()
	defer func() { _ = reader.Close() }()

	sampleIPv4 := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x08, 0x08, 0x08, 0x08,
		10, 88, 0, 5,
		0x00, 0x50, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00,
	}

	var wg sync.WaitGroup
	workers := 10
	pktsPerWorker := 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < pktsPerWorker; i++ {
				mockDev.packets <- append([]byte(nil), sampleIPv4...)
			}
		}()
	}

	wg.Wait()

	received := 0
	timeout := time.After(3 * time.Second)
	expectedTotal := workers * pktsPerWorker

	for received < expectedTotal {
		select {
		case <-testConn.writes:
			received++
		case <-timeout:
			t.Fatalf("timed out waiting for high concurrency packets: got %d, expected %d", received, expectedTotal)
		}
	}
}
