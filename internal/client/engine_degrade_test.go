// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

// degradeEngine 构造一个与 TestStage1_StartEnablesWebRTCActive 相同的可启动引擎（模拟拨号），
// 由调用方决定虚拟网卡与 CONNECT-IP 的行为。
func degradeEngine(t *testing.T) *Engine {
	t.Helper()
	eng := NewEngine()
	eng.SetMode("tun")
	applied := &Applied{
		Servers: []ServerConfig{{Name: "US-Node", Address: "198.51.100.1:443", Token: "tok_degrade", SNI: "us.example.com"}},
		Tokens:  map[string]string{"198.51.100.1:443": "tok_degrade"},
		SNIs:    map[string]string{"198.51.100.1:443": "us.example.com"},
	}
	if err := eng.Apply(applied); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	SetQUICDialHook(func(ctx context.Context, pconn net.PacketConn, remoteAddr net.Addr, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
		return nil, nil
	})
	t.Cleanup(func() { SetQUICDialHook(nil) })
	useFakeTunHost(t, nil)
	return eng
}

// 虚拟网卡创建失败（没提权、缺驱动、驱动启动失败…）：不让连接整体失败，降级为仅本地代理并明确标出；
// 对外报告的模式是 sysproxy；没有任何网卡/路由被创建；停止后降级标记清除。
func TestEngineDegradesToLocalProxyWhenTunAdapterFails(t *testing.T) {
	eng := degradeEngine(t)
	origDialIP := dialIPFn
	defer func() { dialIPFn = origDialIP }()
	dialIPFn = func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		return newMockIPPacketConn(), "10.88.0.2/24", nil
	}
	origOpen := openTunHostFn
	defer func() { openTunHostFn = origOpen }()
	openTunHostFn = func(tunHostConfig) (tunHost, error) {
		return nil, errors.New("create wintun adapter aero0 [process is not elevated: run as Administrator]: Access is denied.")
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("网卡不可用时应降级而不是失败，got %v", err)
	}
	st := eng.GetState()
	if !st.Connected || !st.Degraded {
		t.Fatalf("应为已连接且已降级: connected=%v degraded=%v", st.Connected, st.Degraded)
	}
	if st.Mode != "sysproxy" {
		t.Errorf("降级后对外模式应是 sysproxy，got %q", st.Mode)
	}
	if st.DegradedReason == "" {
		t.Error("应带出降级原因")
	}
	if want := "not elevated"; !contains(st.DegradedReason, want) {
		t.Errorf("降级原因应保留引擎的原始错误（界面据此给出具体提示）: %q", st.DegradedReason)
	}
	if eng.tunHost != nil || eng.stackEngine != nil {
		t.Error("降级时不应留有网卡或数据泵")
	}
	if !st.ResidentListening {
		// 本机默认端口可能被占，但回退后仍应在监听
		t.Error("降级后本地代理应在监听")
	}

	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if st := eng.GetState(); st.Degraded || st.DegradedReason != "" {
		t.Errorf("停止后应清除降级标记: %+v", st)
	}
}

// 网络/拨号失败（不是网卡问题）不得被“降级”掩盖：照常报错、不进入运行态。
func TestEngineDoesNotDegradeOnDialFailure(t *testing.T) {
	eng := degradeEngine(t)
	origDialIP := dialIPFn
	defer func() { dialIPFn = origDialIP }()
	dialIPFn = func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		return nil, "", errors.New("connect-ip refused")
	}
	origOpen := openTunHostFn
	defer func() { openTunHostFn = origOpen }()
	openTunHostFn = func(tunHostConfig) (tunHost, error) {
		t.Error("拨号失败时不应走到创建网卡")
		return nil, errors.New("unexpected")
	}

	err := eng.Start()
	if err == nil {
		_ = eng.Stop()
		t.Fatal("拨号失败应报错")
	}
	if errors.Is(err, ErrTunUnavailable) {
		t.Errorf("拨号失败不应被标记为网卡不可用: %v", err)
	}
	if st := eng.GetState(); st.Degraded || st.Connected {
		t.Errorf("拨号失败不应降级或已连接: %+v", st)
	}
}

// 网卡正常时不降级，且仍报告 tun。
func TestEngineNoDegradeWhenTunWorks(t *testing.T) {
	eng := degradeEngine(t)
	origDialIP := dialIPFn
	defer func() { dialIPFn = origDialIP }()
	dialIPFn = func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		return newMockIPPacketConn(), "10.88.0.2/24", nil
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()
	if st := eng.GetState(); st.Degraded || st.Mode != "tun" || !st.Connected {
		t.Errorf("正常时应为 tun 且未降级: %+v", st)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
