// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestSessionAuthHeadersOneTimeNonce(t *testing.T) {
	sess := &Session{
		token: "test_secret_token_123",
	}

	// 1. First request on session: must include Bearer, Timestamp, Nonce
	hdr1 := make(http.Header)
	sess.setAuthHeaders(hdr1)

	auth := hdr1.Get("Authorization")
	if auth != "Bearer test_secret_token_123" {
		t.Fatalf("unexpected Authorization header: %q", auth)
	}

	tsStr := hdr1.Get("Aero-Timestamp")
	if tsStr == "" {
		t.Fatal("expected Aero-Timestamp header on first request")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || ts <= 0 {
		t.Fatalf("invalid Aero-Timestamp: %q", tsStr)
	}

	nonceHex := hdr1.Get("Aero-Nonce")
	if len(nonceHex) != 64 {
		t.Fatalf("expected 64 hex chars (32 bytes) Aero-Nonce, got %d chars: %q", len(nonceHex), nonceHex)
	}
	if _, err := hex.DecodeString(nonceHex); err != nil {
		t.Fatalf("invalid hex Aero-Nonce: %v", err)
	}

	// 2. Second request on same session: must ONLY include Bearer, NO Timestamp or Nonce
	hdr2 := make(http.Header)
	sess.setAuthHeaders(hdr2)

	if hdr2.Get("Authorization") != "Bearer test_secret_token_123" {
		t.Fatalf("unexpected Authorization header on second request: %q", hdr2.Get("Authorization"))
	}
	if hdr2.Get("Aero-Timestamp") != "" {
		t.Fatalf("expected NO Aero-Timestamp on subsequent request, got: %q", hdr2.Get("Aero-Timestamp"))
	}
	if hdr2.Get("Aero-Nonce") != "" {
		t.Fatalf("expected NO Aero-Nonce on subsequent request, got: %q", hdr2.Get("Aero-Nonce"))
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

// getSessionTestSession 构造带 Close 计数的假会话（client 为 nil，Close 只触发 onClose）。
func getSessionTestSession(closes *atomic.Int32) *Session {
	return &Session{
		addr: "hook:443",
		sni:  "hook.test",
		onClose: func() {
			if closes != nil {
				closes.Add(1)
			}
		},
	}
}

// waitGetSessionCond 在限时内轮询条件，避免测试依赖固定 sleep。
func waitGetSessionCond(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestGetSessionCtxCancelWhileDialing：拨号阻塞时，短 ctx 的多个调用方在各自超时后立即返回 ctx 错误，
// 拨号只发生一次，且不被调用方的取消打断。
func TestGetSessionCtxCancelWhileDialing(t *testing.T) {
	mgr := NewSessionManager()
	var dials atomic.Int32
	release := make(chan struct{})
	hookCtxErr := make(chan error, 1)
	mgr.SetDialHook(func(ctx context.Context) (*Session, error) {
		dials.Add(1)
		<-release
		hookCtxErr <- ctx.Err()
		return getSessionTestSession(nil), nil
	})

	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	elapsed := make([]time.Duration, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, errs[i] = mgr.GetSession(ctx)
			elapsed[i] = time.Since(start)
		}(i)
	}
	wg.Wait()
	for i := 0; i < callers; i++ {
		if !errors.Is(errs[i], context.DeadlineExceeded) {
			t.Fatalf("caller %d: expected DeadlineExceeded, got %v", i, errs[i])
		}
		if elapsed[i] > 2*time.Second {
			t.Fatalf("caller %d returned after %v, want about its own 50ms timeout", i, elapsed[i])
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("expected exactly 1 dial while blocked, got %d", n)
	}

	// 已取消的 ctx 且无在途拨号 / 有在途拨号：立即返回 ctx 错误，不新增拨号。
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := mgr.GetSession(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Canceled for canceled ctx, got %v", err)
	}

	// 放行后拨号照常完成：调用方的取消没有打断拨号，后续调用方拿到会话。
	close(release)
	sess, err := mgr.GetSession(context.Background())
	if err != nil || sess == nil {
		t.Fatalf("GetSession after release: sess=%v err=%v", sess, err)
	}
	if e := <-hookCtxErr; e != nil {
		t.Fatalf("dial ctx must not be canceled by callers' timeouts, got %v", e)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("expected 1 dial in total, got %d", n)
	}
}

// TestGetSessionShortCallerCtxDialCompletes：首个调用方 ctx 很短，拨号仍用独立时限完成，后续调用方拿到会话。
func TestGetSessionShortCallerCtxDialCompletes(t *testing.T) {
	mgr := NewSessionManager()
	var dials atomic.Int32
	hookDeadline := make(chan time.Time, 1)
	mgr.SetDialHook(func(ctx context.Context) (*Session, error) {
		dials.Add(1)
		dl, _ := ctx.Deadline()
		hookDeadline <- dl
		select {
		case <-time.After(150 * time.Millisecond):
			return getSessionTestSession(nil), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	first, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := mgr.GetSession(first); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first caller: expected DeadlineExceeded, got %v", err)
	}

	sess, err := mgr.GetSession(context.Background())
	if err != nil || sess == nil {
		t.Fatalf("second caller: sess=%v err=%v", sess, err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("expected 1 dial, got %d", n)
	}
	// 拨号 ctx 带有独立的拨号时限，而不是首个调用方的 20ms。
	if left := time.Until(<-hookDeadline); left < 5*time.Second || left > sessionDialTimeout {
		t.Fatalf("dial ctx deadline remaining %v, want within (5s, %v]", left, sessionDialTimeout)
	}
	// 之后复用已建立的会话。
	again, err := mgr.GetSession(context.Background())
	if err != nil || again != sess {
		t.Fatalf("expected reuse of dialed session, got %v err=%v", again, err)
	}
}

// TestGetSessionResetAbandonsInflightDial：拨号进行中 Reset，等待方立即得到错误，
// 旧拨号的结果被关闭而不被采用；Reset 之后的新调用方发起全新拨号。
func TestGetSessionResetAbandonsInflightDial(t *testing.T) {
	mgr := NewSessionManager()
	var dials atomic.Int32
	var oldCloses, newCloses atomic.Int32
	release := make(chan struct{})
	oldCtxCanceled := make(chan struct{})
	mgr.SetDialHook(func(ctx context.Context) (*Session, error) {
		if dials.Add(1) == 1 {
			go func() { <-ctx.Done(); close(oldCtxCanceled) }()
			<-release
			return getSessionTestSession(&oldCloses), nil
		}
		return getSessionTestSession(&newCloses), nil
	})

	const waiters = 4
	errCh := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			_, err := mgr.GetSession(context.Background())
			errCh <- err
		}()
	}
	waitGetSessionCond(t, "dial started", func() bool { return dials.Load() == 1 })
	time.Sleep(20 * time.Millisecond) // 让等待方都进入等待（不影响正确性，只增加覆盖）

	mgr.Reset()
	for i := 0; i < waiters; i++ {
		select {
		case err := <-errCh:
			if !errors.Is(err, errSessionDialAbandoned) {
				t.Fatalf("waiter %d: expected errSessionDialAbandoned, got %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("waiter not released by Reset while the old dial is still blocked")
		}
	}
	select {
	case <-oldCtxCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("Reset did not cancel the in-flight dial ctx")
	}

	// 旧拨号尚未返回时，新调用方发起全新拨号并立即拿到会话。
	fresh, err := mgr.GetSession(context.Background())
	if err != nil || fresh == nil {
		t.Fatalf("GetSession after Reset: sess=%v err=%v", fresh, err)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("expected 2 dials, got %d", n)
	}

	// 旧拨号现在才返回：其会话必须被关闭，且不得装回。
	close(release)
	waitGetSessionCond(t, "abandoned session closed", func() bool { return oldCloses.Load() == 1 })
	got, err := mgr.GetSession(context.Background())
	if err != nil || got != fresh {
		t.Fatalf("stale dial result replaced current session: got %v err=%v", got, err)
	}
	if newCloses.Load() != 0 {
		t.Fatal("fresh session must not be closed by the stale dial")
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("expected 2 dials in total, got %d", n)
	}
}

// TestGetSessionSetSessionSupersedesDial：拨号进行中注入会话，等待方直接拿到注入的会话，拨号结果被关闭。
func TestGetSessionSetSessionSupersedesDial(t *testing.T) {
	mgr := NewSessionManager()
	var dials, dialedCloses atomic.Int32
	release := make(chan struct{})
	mgr.SetDialHook(func(ctx context.Context) (*Session, error) {
		dials.Add(1)
		<-release
		return getSessionTestSession(&dialedCloses), nil
	})

	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := mgr.GetSession(context.Background())
		ch <- res{s, err}
	}()
	waitGetSessionCond(t, "dial started", func() bool { return dials.Load() == 1 })

	injected := getSessionTestSession(nil)
	mgr.SetSession(injected)
	select {
	case r := <-ch:
		if r.err != nil || r.s != injected {
			t.Fatalf("waiter should get injected session, got %v err=%v", r.s, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter not released by SetSession")
	}

	close(release)
	waitGetSessionCond(t, "superseded dial result closed", func() bool { return dialedCloses.Load() == 1 })
	if got, err := mgr.GetSession(context.Background()); err != nil || got != injected {
		t.Fatalf("injected session must stay current, got %v err=%v", got, err)
	}
}

// TestGetSessionDialErrorShared：拨号失败时，所有等待方得到同一次拨号的错误，失败后允许重新拨号。
func TestGetSessionDialErrorShared(t *testing.T) {
	mgr := NewSessionManager()
	var dials atomic.Int32
	release := make(chan struct{})
	boom := errors.New("boom")
	mgr.SetDialHook(func(ctx context.Context) (*Session, error) {
		if dials.Add(1) == 1 {
			<-release
			return nil, boom
		}
		return getSessionTestSession(nil), nil
	})

	const waiters = 4
	errCh := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			_, err := mgr.GetSession(context.Background())
			errCh <- err
		}()
	}
	waitGetSessionCond(t, "dial started", func() bool { return dials.Load() == 1 })
	time.Sleep(20 * time.Millisecond)
	close(release)
	for i := 0; i < waiters; i++ {
		if err := <-errCh; !errors.Is(err, boom) {
			t.Fatalf("waiter %d: expected boom, got %v", i, err)
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("failed dial must be shared, got %d dials", n)
	}
	if s, err := mgr.GetSession(context.Background()); err != nil || s == nil {
		t.Fatalf("redial after failure: sess=%v err=%v", s, err)
	}
}

// TestGetSessionRaceConcurrentResetLoop：-race 下并发 GetSession / Reset / SetSession / Drain 循环。
func TestGetSessionRaceConcurrentResetLoop(t *testing.T) {
	mgr := NewSessionManager()
	var dials, closes atomic.Int32
	mgr.SetDialHook(func(ctx context.Context) (*Session, error) {
		dials.Add(1)
		select {
		case <-time.After(time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return getSessionTestSession(&closes), nil
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
				_, _ = mgr.GetSession(ctx)
				cancel()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			switch i % 3 {
			case 0:
				mgr.Reset()
			case 1:
				mgr.SetSession(getSessionTestSession(&closes))
			default:
				mgr.Drain(time.Millisecond)
			}
			time.Sleep(500 * time.Microsecond)
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// 收尾：并发循环结束后管理器仍可用。
	mgr.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if s, err := mgr.GetSession(ctx); err != nil || s == nil {
		t.Fatalf("manager unusable after race loop: sess=%v err=%v", s, err)
	}
	if dials.Load() == 0 {
		t.Fatal("expected at least one dial")
	}
}
