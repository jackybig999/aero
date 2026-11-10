// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

func TestSessionManagerLifecycle(t *testing.T) {
	mgr := NewSessionManager()
	if mgr == nil {
		t.Fatal("expected non-nil SessionManager")
	}

	mgr.Reset()
	if mgr.currentSession != nil {
		t.Fatal("expected nil session after Reset")
	}
}

func TestSessionAuthHeadersBearerOnly(t *testing.T) {
	s := &Session{token: "tok_abc"}
	for i := 0; i < 2; i++ {
		hdr := http.Header{}
		s.setAuthHeaders(hdr)
		if got := hdr.Get("Authorization"); got != "Bearer tok_abc" {
			t.Fatalf("request %d Authorization = %q, want Bearer tok_abc", i, got)
		}
		if hdr.Get("Aero-Timestamp") != "" || hdr.Get("Aero-Nonce") != "" {
			t.Fatalf("request %d still sends deprecated Aero-Timestamp/Aero-Nonce (C3 §5)", i)
		}
	}
}

type mockStreamPipe struct {
	net.Conn
}

func TestH3StreamConnWrapper(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	conn := &h3StreamConn{
		target: "example.com:443",
	}

	// Test address parsing
	rAddr := conn.RemoteAddr()
	if rAddr.String() != "example.com:443" && !bytes.Contains([]byte(rAddr.String()), []byte("443")) {
		t.Fatalf("unexpected RemoteAddr: %v", rAddr)
	}

	lAddr := conn.LocalAddr()
	if lAddr.Network() != "tcp" {
		t.Fatalf("unexpected LocalAddr: %v", lAddr)
	}

	// Test Close idempotency
	_ = c1.Close()
	if err := conn.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if !conn.closed.Load() {
		t.Fatal("expected closed flag to be true")
	}

	// Write on closed returns EOF or ErrClosedPipe
	_, werr := conn.Write([]byte("data"))
	if !errors.Is(werr, io.ErrClosedPipe) {
		t.Fatalf("expected io.ErrClosedPipe, got %v", werr)
	}

	// Read on closed returns EOF
	buf := make([]byte, 10)
	_, rerr := conn.Read(buf)
	if !errors.Is(rerr, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", rerr)
	}
}

func TestSessionManagerHooks(t *testing.T) {
	mgr := NewSessionManager()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	calledDial := false
	mgr.SetDialHook(func(ctx context.Context) (*Session, error) {
		calledDial = true
		return &Session{
			token: "hook_token",
			addr:  "127.0.0.1:443",
			sni:   "node.aero",
		}, nil
	})

	sess, err := mgr.GetSession(context.Background())
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if !calledDial {
		t.Fatal("expected dialHook to be called")
	}
	if sess.token != "hook_token" {
		t.Fatalf("expected hook_token, got %s", sess.token)
	}

	// Subsequent GetSession reuses active session
	calledDial = false
	sess2, err := mgr.GetSession(context.Background())
	if err != nil {
		t.Fatalf("GetSession 2 failed: %v", err)
	}
	if calledDial {
		t.Fatal("expected session reuse, dialHook called again")
	}
	if sess2 != sess {
		t.Fatal("expected same session instance")
	}

	// Reset clears session, causing dialHook to be called on next GetSession
	mgr.Reset()
	calledDial = false
	_, err = mgr.GetSession(context.Background())
	if err != nil {
		t.Fatalf("GetSession 3 failed: %v", err)
	}
	if !calledDial {
		t.Fatal("expected dialHook to be called after Reset")
	}
}

func TestEngineSessionManagerWiring(t *testing.T) {
	eng := NewEngine()
	if eng.SessionManager() == nil {
		t.Fatal("expected non-nil SessionManager in Engine")
	}

	// Verify DoH resolver is wired in dnsHandler
	if eng.dnsHandler.dohResolver == nil {
		t.Fatal("expected dnsHandler.dohResolver to be wired")
	}

	// Verify SessionManager is wired in tunnelClient
	if eng.tunnelClient.sessionMgr == nil {
		t.Fatal("expected tunnelClient.sessionMgr to be wired")
	}

	// Test custom TCP dialer in Engine
	mockConn, serverConn := net.Pipe()
	defer serverConn.Close()

	calledCustom := false
	eng.SetTCPDialer(func(ctx context.Context, target string) (net.Conn, error) {
		calledCustom = true
		return mockConn, nil
	})

	conn, err := eng.DialTCP(context.Background(), "1.2.3.4:80")
	if err != nil {
		t.Fatalf("DialTCP failed: %v", err)
	}
	if !calledCustom {
		t.Fatal("expected custom dialer to be called")
	}

	// Verify trackedConn tracking in activeConns
	count := 0
	eng.activeConns.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 1 {
		t.Fatalf("expected 1 tracked conn, got %d", count)
	}

	// Close conn and verify deletion from activeConns
	_ = conn.Close()
	count = 0
	eng.activeConns.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Fatalf("expected 0 tracked conns after close, got %d", count)
	}
}

func TestPingActiveNodeViaSessionManager(t *testing.T) {
	eng := NewEngine()

	// Inject a session that responds to Ping
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	pingCalled := false
	sess := &Session{
		token: "test_ping_token",
	}

	eng.SessionManager().SetDialHook(func(ctx context.Context) (*Session, error) {
		return sess, nil
	})

	// When ping fails (h3Conn is nil), PingActiveNode returns error gracefully
	_, err := eng.PingActiveNode(context.Background())
	if err == nil {
		t.Fatal("expected error with uninitialized h3Conn in Ping")
	}
	_ = pingCalled
}

func TestDialIPPrefixValidation(t *testing.T) {
	// Verify netip.Prefix parsing and formatting
	prefix, err := netip.ParsePrefix("10.88.0.2/16")
	if err != nil {
		t.Fatalf("parse prefix failed: %v", err)
	}
	if prefix.String() != "10.88.0.2/16" {
		t.Fatalf("unexpected prefix string: %s", prefix.String())
	}
	if prefix.Addr().String() != "10.88.0.2" {
		t.Fatalf("unexpected addr: %s", prefix.Addr().String())
	}
}

func TestSocks5UDPAssociateHandling(t *testing.T) {
	eng := NewEngine()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go eng.serveMixedConn(serverConn)

	// 1. SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	if _, err := clientConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting failed: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("read greeting resp failed: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected greeting resp: %v", resp)
	}

	// 2. Send UDP ASSOCIATE request (CMD=0x03, ATYP=0x01, 0.0.0.0:0)
	if _, err := clientConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write udp associate request failed: %v", err)
	}
	assocResp := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, assocResp); err != nil {
		t.Fatalf("read udp associate resp failed: %v", err)
	}
	if assocResp[0] != 0x05 || assocResp[1] != 0x00 {
		t.Fatalf("udp associate rejected with code: %d", assocResp[1])
	}
	assignedPort := binary.BigEndian.Uint16(assocResp[8:10])
	if assignedPort == 0 {
		t.Fatal("expected assigned UDP port > 0")
	}
}

// TestSessionManager_SetSession 验证会话单例注入与复用，杜绝二次拨号
func TestSessionManager_SetSession(t *testing.T) {
	mgr := NewSessionManager()
	dialCount := 0
	mgr.SetDialHook(func(ctx context.Context) (*Session, error) {
		dialCount++
		return &Session{addr: "hook:443", sni: "hook.com"}, nil
	})

	injected := &Session{addr: "injected:443", sni: "injected.com"}
	mgr.SetSession(injected)

	// GetSession 必须直接返回注入的会话，绝不触发 dialHook
	sess, err := mgr.GetSession(context.Background())
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sess != injected {
		t.Fatalf("expected injected session %v, got %v", injected, sess)
	}
	if dialCount != 0 {
		t.Fatalf("expected 0 dial hook calls, got %d", dialCount)
	}

	// 再次注入新 session，原 session 应当被替换
	injected2 := &Session{addr: "injected2:443", sni: "injected2.com"}
	mgr.SetSession(injected2)
	sess2, err := mgr.GetSession(context.Background())
	if err != nil {
		t.Fatalf("GetSession 2 failed: %v", err)
	}
	if sess2 != injected2 {
		t.Fatalf("expected second session, got %v", sess2)
	}
}
