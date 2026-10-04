// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// TestCopyTunnel_BidirectionalLossless 验证 CopyTunnel 的无损双向流转 (P5 规范)
// 使用 net.Pipe() 充当两端，向一端写入 IP 包，断言另一端读到完全相同的字节
func TestCopyTunnel_BidirectionalLossless(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 模拟 TUN 虚拟网卡端：tunSide 传给 CopyTunnel，testTun 由测试代码读写
	tunSide, testTun := net.Pipe()
	defer testTun.Close()

	// 模拟 IP 传输通道端：ipSide 传给 CopyTunnel，testIP 由测试代码读写
	ipSide, testIP := net.Pipe()
	defer testIP.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyTunnel(ctx, tunSide, ipSide)
	}()

	// 1. 测试 TUN -> IP 通道无损转发
	tunPacket := []byte{
		0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x0a, 0x58, 0x00, 0x02,
		0x08, 0x08, 0x08, 0x08, 0x04, 0xd2, 0x00, 0x50,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(tunPacket))
		n, err := testIP.Read(buf)
		if err != nil {
			t.Errorf("read from testIP failed: %v", err)
			return
		}
		if n != len(tunPacket) || !bytes.Equal(buf[:n], tunPacket) {
			t.Errorf("TUN->IP packet mismatch: got %x, want %x", buf[:n], tunPacket)
		}
	}()

	if _, err := testTun.Write(tunPacket); err != nil {
		t.Fatalf("write to testTun failed: %v", err)
	}
	wg.Wait()

	// 2. 测试 IP 通道 -> TUN 无损转发
	ipPacket := []byte{
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00,
		0x38, 0x06, 0x00, 0x00, 0x08, 0x08, 0x08, 0x08,
		0x0a, 0x58, 0x00, 0x02, 0x00, 0x50, 0x04, 0xd2,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(ipPacket))
		n, err := testTun.Read(buf)
		if err != nil {
			t.Errorf("read from testTun failed: %v", err)
			return
		}
		if n != len(ipPacket) || !bytes.Equal(buf[:n], ipPacket) {
			t.Errorf("IP->TUN packet mismatch: got %x, want %x", buf[:n], ipPacket)
		}
	}()

	if _, err := testIP.Write(ipPacket); err != nil {
		t.Fatalf("write to testIP failed: %v", err)
	}
	wg.Wait()

	// 3. 正常关闭与资源回收测试
	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("CopyTunnel unexpected exit error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CopyTunnel did not exit upon context cancellation")
	}
}

// TestUDPUnavailableFallback_NoTUN_Port55555Listening (P4 规范验证桩)
// 模式是 tun 而 UDP/443（QUIC/HTTP/3）拨号失败时：
// 不调用 OpenTunDevice，不装 /1 路由，55555 照常监听，向 UI 返回固定错误码 UDP_UNAVAILABLE。
func TestUDPUnavailableFallback_NoTUN_Port55555Listening(t *testing.T) {
	origDetect := detectThirdPartyTUN
	defer func() { detectThirdPartyTUN = origDetect }()
	detectThirdPartyTUN = func() (bool, string, error) {
		return false, "", nil
	}

	// 拦截并模拟 UDP 拨号失败（模拟目标 UDP 443 被防火墙静默丢包或阻断）
	origHook := quicDialHook
	defer func() { SetQUICDialHook(origHook) }()
	SetQUICDialHook(func(ctx context.Context, pconn net.PacketConn, remoteAddr net.Addr, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
		return nil, errors.New("UDP port 443 blocked by DPI / connection refused")
	})

	eng := NewEngine()
	eng.SetMode("tun")
	eng.SetListenAddr("127.0.0.1:0") // 单元测试绑定动态端口避免端口冲突

	eng.activeAddr = "127.0.0.1:443"
	eng.activeToken = "test-token-p4"
	eng.activeSNI = "127.0.0.1"

	err := eng.Start()
	if err == nil {
		t.Fatal("expected eng.Start() to fail when UDP dial is blocked, got nil")
	}

	// 1. 断言向调用方返回固定错误码 UDP_UNAVAILABLE
	if !errors.Is(err, ErrUDPUnavailable) && !strings.Contains(err.Error(), "UDP_UNAVAILABLE") {
		t.Fatalf("expected ErrUDPUnavailable in error, got: %v", err)
	}

	// 2. 断言 TUN 设备未打开
	if eng.tunDevice != nil {
		t.Fatal("TUN device must NOT be opened when UDP dial fails in tun mode")
	}

	// 3. 断言本地代理端口照常监听（55555 照常监听，供应用/浏览器使用，不装 /1 路由）
	if eng.mixedListener == nil {
		t.Fatal("mixed proxy listener (55555) must be active and listening")
	}

	// 4. 清理资源
	_ = eng.Stop()
	if eng.mixedListener != nil {
		t.Fatal("mixed listener must be closed after Stop()")
	}
}

// TestPhase8Gate_MobilePipelineTeardown (Phase 8 Gate)
// 验证移动端控制器管道双向流转与优雅退出
func TestPhase8Gate_MobilePipelineTeardown(t *testing.T) {
	tunSide, testTun := net.Pipe()
	ipSide, testIP := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctrl := StartMobileTunnel(ctx, tunSide, ipSide)

	// 1. 验证数据双向流转成功
	tunPacket := []byte{0x45, 0x00, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04, 0x10, 0x20, 0x30, 0x40}
	ipPacket := []byte{0x45, 0x00, 0x00, 0x20, 0x05, 0x06, 0x07, 0x08, 0x50, 0x60, 0x70, 0x80}

	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 1024)
		n, err := testIP.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(buf[:n], tunPacket) {
			errCh <- fmt.Errorf("tun->ip packet mismatch: got %x, want %x", buf[:n], tunPacket)
			return
		}
		errCh <- nil
	}()

	if _, err := testTun.Write(tunPacket); err != nil {
		t.Fatalf("write to testTun failed: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("tun->ip verification failed: %v", err)
	}

	go func() {
		buf := make([]byte, 1024)
		n, err := testTun.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(buf[:n], ipPacket) {
			errCh <- fmt.Errorf("ip->tun packet mismatch: got %x, want %x", buf[:n], ipPacket)
			return
		}
		errCh <- nil
	}()

	if _, err := testIP.Write(ipPacket); err != nil {
		t.Fatalf("write to testIP failed: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("ip->tun verification failed: %v", err)
	}

	// 2. 调用 Stop()，验证在 200ms 内 done 通道关闭
	stopStart := time.Now()
	stopErr := ctrl.Stop()
	elapsed := time.Since(stopStart)
	if elapsed > 200*time.Millisecond {
		t.Fatalf("Stop() took %v, exceeded 200ms budget", elapsed)
	}
	if stopErr != nil {
		t.Fatalf("Stop() returned unexpected error: %v", stopErr)
	}

	select {
	case <-ctrl.done:
	default:
		t.Fatalf("ctrl.done channel not closed after Stop()")
	}

	// 3. 验证双端句柄安全释放 (底层已关闭，写入报错)
	_, tunErr := testTun.Write([]byte{0x01})
	if tunErr == nil {
		t.Fatalf("expected write to testTun to fail after Stop(), got nil")
	}
	_, ipErr := testIP.Write([]byte{0x01})
	if ipErr == nil {
		t.Fatalf("expected write to testIP to fail after Stop(), got nil")
	}
	_ = testTun.Close()
	_ = testIP.Close()

	// 4. 验证零协程泄露 (CopyTunnel goroutines fully reaped)
	for i := 0; i < 20; i++ {
		time.Sleep(5 * time.Millisecond)
		buf := make([]byte, 65536)
		n := runtime.Stack(buf, true)
		stackStr := string(buf[:n])
		if !strings.Contains(stackStr, "CopyTunnel.func") && !strings.Contains(stackStr, "StartMobileTunnel.func") {
			break
		}
		if i == 19 {
			t.Fatalf("goroutine leak detected in CopyTunnel:\n%s", stackStr)
		}
	}
}

// TestFinalGate_MobileBufPool 验证 1500 字节缓冲池正常流转与快速释放及移动端运行时压制
func TestFinalGate_MobileBufPool(t *testing.T) {
	// 1. 验证移动端运行时压制函数可无错误执行
	InitMobileRuntime()

	// 2. 验证缓冲池获取到的对象为 1500 字节切片
	bufPtr := mobileBufPool.Get().(*[]byte)
	if bufPtr == nil {
		t.Fatalf("expected non-nil buffer pointer from mobileBufPool")
	}
	if len(*bufPtr) != 1500 {
		t.Fatalf("expected buffer length 1500, got %d", len(*bufPtr))
	}
	// 归还缓冲池
	mobileBufPool.Put(bufPtr)

	// 3. 验证通过 CopyTunnel 正常传输完整 1500 字节 MTU 数据包
	tunSide, testTun := net.Pipe()
	defer testTun.Close()
	ipSide, testIP := net.Pipe()
	defer testIP.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyTunnel(ctx, tunSide, ipSide)
	}()

	packet1500 := make([]byte, 1500)
	packet1500[0] = 0x45 // IPv4
	packet1500[1499] = 0xFF

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		recvBuf := make([]byte, 2000)
		n, err := testIP.Read(recvBuf)
		if err != nil {
			t.Errorf("read from testIP failed: %v", err)
			return
		}
		if n != 1500 || !bytes.Equal(recvBuf[:n], packet1500) {
			t.Errorf("packet mismatch: got %d bytes, want 1500", n)
		}
	}()

	if _, err := testTun.Write(packet1500); err != nil {
		t.Fatalf("write to testTun failed: %v", err)
	}
	wg.Wait()

	// 优雅关闭并释放
	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected CopyTunnel exit error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("CopyTunnel did not exit in time")
	}
}
