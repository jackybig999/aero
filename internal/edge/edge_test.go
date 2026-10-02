// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aero-protocol/aero/internal/proto"
	"github.com/quic-go/quic-go"
)

func TestDatagramFramingAndProtoCodec(t *testing.T) {
	ctxID := uint32(1001)
	payload := []byte("hello udp world")
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], ctxID)
	copy(frame[4:], payload)

	parsedID := binary.BigEndian.Uint32(frame[:4])
	if parsedID != ctxID {
		t.Fatalf("expected contextID %d, got %d", ctxID, parsedID)
	}
	if string(frame[4:]) != string(payload) {
		t.Fatalf("expected payload %s, got %s", payload, frame[4:])
	}

	req := &proto.ConnectRequest{
		Token:     "test_token_123",
		Timestamp: uint64(time.Now().UnixMilli()),
		Nonce:     []byte("test_nonce"),
		Streams: []*proto.StreamSpec{
			{
				StreamId:   ctxID,
				StreamType: proto.StreamType_UDP,
				TargetHost: "1.2.3.4",
				TargetPort: 443,
			},
		},
	}

	pr, pw := net.Pipe()
	go func() {
		defer pw.Close()
		_ = proto.WriteMessage(pw, req)
	}()

	var received proto.ConnectRequest
	if err := proto.ReadMessage(pr, &received); err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	if received.Token != req.Token {
		t.Fatalf("expected token %s, got %s", req.Token, received.Token)
	}
	if len(received.Streams) != 1 || received.Streams[0].StreamId != ctxID {
		t.Fatalf("expected stream ID %d", ctxID)
	}
}

// ==========================================
// 1. Tests for Limiters (limit.go)
// ==========================================

func TestConnLimiter(t *testing.T) {
	cl := NewConnLimiter(10, 2)

	// Acquire 2 for user1
	if !cl.TryAcquire("user1") {
		t.Fatal("expected user1 acquire 1 to succeed")
	}
	if !cl.TryAcquire("user1") {
		t.Fatal("expected user1 acquire 2 to succeed")
	}
	// 3rd for user1 should fail (maxPerTok = 2)
	if cl.TryAcquire("user1") {
		t.Fatal("expected user1 acquire 3 to fail due to per-token limit")
	}

	// user2 should succeed
	if !cl.TryAcquire("user2") {
		t.Fatal("expected user2 acquire to succeed")
	}

	if cl.Active() != 3 {
		t.Fatalf("expected 3 active conns, got %d", cl.Active())
	}
	if cl.ActiveToken("user1") != 2 {
		t.Fatalf("expected 2 active conns for user1, got %d", cl.ActiveToken("user1"))
	}

	// Release 1 for user1
	cl.Release("user1")
	if cl.ActiveToken("user1") != 1 {
		t.Fatalf("expected 1 active conn for user1, got %d", cl.ActiveToken("user1"))
	}

	// Now user1 can acquire again
	if !cl.TryAcquire("user1") {
		t.Fatal("expected user1 acquire to succeed after release")
	}
}

func TestBandwidthLimiter(t *testing.T) {
	bl := NewBandwidthLimiter(10000)
	if !bl.Enabled() {
		t.Fatal("expected bandwidth limiter to be enabled")
	}
	if bl.Rate() != 10000 {
		t.Fatalf("expected rate 10000, got %f", bl.Rate())
	}

	// Should not block on reasonable consumption within burst
	start := time.Now()
	bl.Take("user1", 100)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("take within burst should not sleep significantly")
	}
}

func TestDialGuardBlockedTargets(t *testing.T) {
	blocked, _ := IsBlockedTarget("127.0.0.1:80")
	if !blocked {
		t.Fatal("expected 127.0.0.1 to be blocked")
	}
	blocked, _ = IsBlockedTarget("localhost:443")
	if !blocked {
		t.Fatal("expected localhost to be blocked")
	}
	blocked, _ = IsBlockedTarget("192.168.1.1:443")
	if !blocked {
		t.Fatal("expected 192.168.1.1 to be blocked")
	}
	blocked, _ = IsBlockedTarget("10.0.0.1:443")
	if !blocked {
		t.Fatal("expected 10.0.0.1 to be blocked")
	}
	blocked, _ = IsBlockedTarget("100.64.0.1:443")
	if !blocked {
		t.Fatal("expected CGNAT 100.64.0.1 to be blocked")
	}

	// Public domain should be allowed
	blocked, _ = IsBlockedTarget("example.com:443")
	if blocked {
		t.Fatal("expected example.com to be allowed")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(5)
	ip := "1.2.3.4"

	// Initial tokens
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("expected allow on request %d", i)
		}
	}
	// Exceeded
	if rl.Allow(ip) {
		t.Fatal("expected 6th request to be denied")
	}

	// Test Fail Banning
	for i := 0; i < 19; i++ {
		if rl.RecordFail(ip) {
			t.Fatal("should not ban before 20 failures")
		}
	}
	if !rl.RecordFail(ip) {
		t.Fatal("should ban on 20th failure")
	}
	if !rl.IsBanned(ip) {
		t.Fatal("expected ip to be banned")
	}
}

// ==========================================
// 2. Tests for Auth & TokenStore (auth.go)
// ==========================================

func TestValidatorAndTokenStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-edge-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	v := NewValidator()
	store, err := OpenTokenStore(tmpDir, v)
	if err != nil {
		t.Fatalf("open token store: %v", err)
	}

	token := "aero_test_token_12345"
	if err := store.Ensure(token, "admin", 1*time.Hour); err != nil {
		t.Fatalf("ensure token: %v", err)
	}

	if !v.Validate(token) {
		t.Fatal("token should be valid")
	}

	// Test Nonce validation and anti-replay
	ts := uint64(time.Now().UnixMilli())
	nonce1 := []byte("nonce_test_0001")

	if !v.ValidateFull(token, ts, nonce1) {
		t.Fatal("first ValidateFull should succeed")
	}
	// Replay with same nonce must fail!
	if v.ValidateFull(token, ts, nonce1) {
		t.Fatal("replay of nonce1 must fail")
	}

	// New nonce should succeed
	nonce2 := []byte("nonce_test_0002")
	if !v.ValidateFull(token, ts, nonce2) {
		t.Fatal("ValidateFull with nonce2 should succeed")
	}

	// Test reload from disk
	v2 := NewValidator()
	store2, err := OpenTokenStore(tmpDir, v2)
	if err != nil {
		t.Fatalf("open store2: %v", err)
	}
	if !v2.Validate(token) {
		t.Fatal("token should be loaded from tokens.json")
	}
	if store2.v.Count() != 1 {
		t.Fatalf("expected 1 token, got %d", store2.v.Count())
	}
}

// ==========================================
// 3. Tests for Subscriptions (sub.go)
// ==========================================

func TestSubscriptionStoreAndSigning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-sub-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewSubStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	err = store.Ensure(EnsureSubParams{
		Name:    "node-tokyo",
		Address: "1.2.3.4:443",
		Token:   "token_abc",
		SNI:     "tokyo.aero.net",
	})
	if err != nil {
		t.Fatal(err)
	}

	// client-sub.json must exist on disk!
	clientSubPath := filepath.Join(tmpDir, "client-sub.json")
	if _, err := os.Stat(clientSubPath); err != nil {
		t.Fatalf("client-sub.json should be written: %v", err)
	}

	// Verify signature
	doc := store.Document()
	if !VerifySub(doc, []byte("token_abc")) {
		t.Fatal("subscription signature verification failed")
	}

	// Test User Subscription (Slug)
	userSub := UserSub{
		Username: "jacky",
		Slug:     "jacky888abc",
		Token:    "token_jacky",
		ExpireAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	if err := store.UpsertUserSub(userSub); err != nil {
		t.Fatal(err)
	}

	retrieved, ok := store.GetUserSub("jacky888abc")
	if !ok || retrieved.Username != "jacky" {
		t.Fatalf("user sub retrieval failed: %+v", retrieved)
	}

	// Test SubHandler
	handler := &SubHandler{Store: store}

	// 1. GET /sub/superadmin
	reqAdmin := httptest.NewRequest(http.MethodGet, "/sub/superadmin", nil)
	recAdmin := httptest.NewRecorder()
	if !handler.TryServe(recAdmin, reqAdmin) {
		t.Fatal("TryServe should handle /sub/superadmin")
	}
	if recAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recAdmin.Code)
	}

	// 2. GET /sub/jacky888abc (User Slug)
	reqUser := httptest.NewRequest(http.MethodGet, "/sub/jacky888abc", nil)
	recUser := httptest.NewRecorder()
	if !handler.TryServe(recUser, reqUser) {
		t.Fatal("TryServe should handle user slug")
	}
	if recUser.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recUser.Code)
	}
}

// ==========================================
// 4. Tests for Admin API (admin.go)
// ==========================================

func TestAdminHandlerAndTokenSync(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-admin-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	v := NewValidator()
	ts, _ := OpenTokenStore(tmpDir, v)
	ss, _ := NewSubStore(tmpDir)

	admin := NewAdminHandler("my-secret-key", v, ts, ss, nil, nil, nil)

	// Unauthorized request (external IP, no key)
	req := httptest.NewRequest(http.MethodGet, "/admin/version", nil)
	req.RemoteAddr = "203.0.113.195:12345"
	rec := httptest.NewRecorder()
	admin.TryServe(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 forbidden without key, got %d", rec.Code)
	}

	// Authorized request with X-Aero-Admin-Key
	req.Header.Set("X-Aero-Admin-Key", "my-secret-key")
	rec = httptest.NewRecorder()
	admin.TryServe(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with admin key, got %d", rec.Code)
	}

	// POST /admin/subs for midplatform provisioning
	subPayload := `{
		"username": "tester",
		"slug": "tester123456",
		"token": "aero_provisioned_token_999",
		"expire_at": 1893456000
	}`
	reqSub := httptest.NewRequest(http.MethodPost, "/admin/subs", strings.NewReader(subPayload))
	reqSub.Header.Set("X-Aero-Admin-Key", "my-secret-key")
	reqSub.RemoteAddr = "203.0.113.195:12345"
	recSub := httptest.NewRecorder()
	admin.TryServe(recSub, reqSub)
	if recSub.Code != http.StatusOK {
		t.Fatalf("expected 200 on upsert subs, got %d: %s", recSub.Code, recSub.Body.String())
	}

	// Verify token was automatically mounted into TokenStore and Validator!
	if !v.Validate("aero_provisioned_token_999") {
		t.Fatal("provisioned token should be active in Validator immediately")
	}
}

// ==========================================
// 5. Tests for DNS Singleflight & Caching (quic.go)
// ==========================================

func TestDNSResolverSingleflightAndCache(t *testing.T) {
	resolver := NewDNSResolver()

	var lookupCount atomic.Int32
	resolver.SetLookupFunc(func(ctx context.Context, host string) ([]net.IP, error) {
		lookupCount.Add(1)
		time.Sleep(50 * time.Millisecond) // simulate upstream latency
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	})

	token := "test_token"

	// 10 concurrent queries for the same domain
	const concurrent = 10
	var wg sync.WaitGroup
	wg.Add(concurrent)

	for i := 0; i < concurrent; i++ {
		go func() {
			defer wg.Done()
			ip4, err := resolver.Resolve(token, "example.com")
			if err != nil {
				t.Errorf("resolve error: %v", err)
				return
			}
			if len(ip4) != 4 {
				t.Errorf("expected 4 bytes, got %d", len(ip4))
			}
		}()
	}
	wg.Wait()

	// Assert: upstream resolver must be called strictly ONCE due to singleflight!
	if count := lookupCount.Load(); count != 1 {
		t.Fatalf("expected strictly 1 upstream lookup due to singleflight, got %d", count)
	}

	// Subsequent query must hit cache without calling upstream!
	ip4, err := resolver.Resolve(token, "example.com")
	if err != nil {
		t.Fatalf("cached resolve error: %v", err)
	}
	if len(ip4) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(ip4))
	}
	if count := lookupCount.Load(); count != 1 {
		t.Fatalf("expected cache hit with lookup count remaining 1, got %d", count)
	}
}

// ==========================================
// 6. Tests for UDP Context Lifecycle & Limits (quic.go)
// ==========================================

func TestUDPContextLimits(t *testing.T) {
	v := NewValidator()
	v.AddToken("tok_user1", "user", 1*time.Hour)
	v.AddToken("tok_user2", "user", 1*time.Hour)

	server := NewQUICServer(v, nil, nil, nil, nil)

	// Acquire up to MaxUDPContextsPerToken (64)
	for i := 0; i < MaxUDPContextsPerToken; i++ {
		if !server.acquireUDPSlot("tok_user1") {
			t.Fatalf("acquire slot %d for user1 should succeed", i)
		}
	}

	// 65th slot for user1 must be rejected!
	if server.acquireUDPSlot("tok_user1") {
		t.Fatal("65th slot for user1 must be rejected by per-token cap")
	}

	// user2 can still acquire slots!
	if !server.acquireUDPSlot("tok_user2") {
		t.Fatal("user2 should be able to acquire slot")
	}

	// Release 1 for user1
	server.releaseUDPSlot("tok_user1")
	// Now user1 can acquire 1 slot
	if !server.acquireUDPSlot("tok_user1") {
		t.Fatal("user1 should be able to acquire slot after release")
	}
}

// ==========================================
// 7. Tests for MaskToken & Server Lifecycle (serve.go)
// ==========================================

func TestMaskTokenNoPlaintext(t *testing.T) {
	plain := "aero_secret_super_token_99999"
	masked := MaskToken(plain)

	if strings.Contains(masked, "super_token") {
		t.Fatalf("masked token must not contain sensitive plaintext, got %s", masked)
	}
	if !strings.HasPrefix(masked, "aero") || !strings.HasSuffix(masked, "9999") {
		t.Fatalf("masked token should preserve prefix and suffix, got %s", masked)
	}
	if MaskToken("short") != "***" {
		t.Fatalf("short tokens should be masked as ***, got %s", MaskToken("short"))
	}
}

func TestServerCoverAndHealth(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-serve-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := ServerConfig{
		Listen:                     ":18443",
		Domain:                     "localhost",
		DataDir:                    tmpDir,
		AdminKey:                   "adminkey",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Health endpoint test
	reqH := httptest.NewRequest(http.MethodGet, "/health", nil)
	recH := httptest.NewRecorder()
	srv.ServeHTTP(recH, reqH)
	if recH.Code != http.StatusOK {
		t.Fatalf("health expected 200, got %d", recH.Code)
	}
	if recH.Header().Get("Server") != "nginx/1.30.5" {
		t.Fatalf("expected Server 'nginx/1.30.5', got %q", recH.Header().Get("Server"))
	}
	if recH.Header().Get("Alt-Svc") != `h3=":443"; ma=86400` {
		t.Fatalf("expected Alt-Svc 'h3=\":443\"; ma=86400', got %q", recH.Header().Get("Alt-Svc"))
	}

	// Cover site endpoint test
	reqC := httptest.NewRequest(http.MethodGet, "/", nil)
	recC := httptest.NewRecorder()
	srv.ServeHTTP(recC, reqC)
	if recC.Code != http.StatusOK {
		t.Fatalf("cover expected 200, got %d", recC.Code)
	}
	if recC.Header().Get("Server") != "nginx/1.30.5" {
		t.Fatalf("expected Server 'nginx/1.30.5', got %q", recC.Header().Get("Server"))
	}
	if recC.Header().Get("Alt-Svc") != `h3=":443"; ma=86400` {
		t.Fatalf("expected Alt-Svc 'h3=\":443\"; ma=86400', got %q", recC.Header().Get("Alt-Svc"))
	}
	if !strings.Contains(recC.Body.String(), "Global Anycast Acceleration Edge Node") {
		t.Fatalf("cover page missing expected text")
	}
}

func TestServerHTTPHeadersAndNextProtos(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-serve-headers-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := ServerConfig{
		Listen:                     "127.0.0.1:18447",
		Domain:                     "localhost",
		DataDir:                    tmpDir,
		AdminKey:                   "adminkey",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	// 1. Verify NextProtos contains "h2" and "http/1.1"
	if srv.httpServer == nil || srv.httpServer.TLSConfig == nil {
		t.Fatal("httpServer or TLSConfig is nil")
	}
	nextProtos := srv.httpServer.TLSConfig.NextProtos
	hasH2 := false
	hasHTTP11 := false
	for _, p := range nextProtos {
		if p == "h2" {
			hasH2 = true
		}
		if p == "http/1.1" {
			hasHTTP11 = true
		}
	}
	if !hasH2 || !hasHTTP11 {
		t.Fatalf("expected NextProtos to contain h2 and http/1.1, got %v", nextProtos)
	}

	// 2. Verify all HTTP endpoints return Server: nginx/1.30.5 and Alt-Svc: h3=":443"; ma=86400
	endpoints := []string{"/", "/health", "/admin/version", "/sub/nonexistent"}
	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		serverHeader := rec.Header().Get("Server")
		if serverHeader != "nginx/1.30.5" {
			t.Fatalf("endpoint %s expected Server header 'nginx/1.30.5', got %q", ep, serverHeader)
		}

		altSvcHeader := rec.Header().Get("Alt-Svc")
		expectedAltSvc := `h3=":443"; ma=86400`
		if altSvcHeader != expectedAltSvc {
			t.Fatalf("endpoint %s expected Alt-Svc header %q, got %q", ep, expectedAltSvc, altSvcHeader)
		}
	}
}

// ==========================================
// 8. Tests for QUIC Hardening (E-1, E-2, E-3, E-4)
// ==========================================

func TestQUICConfigHardening(t *testing.T) {
	cfg := DefaultQUICConfig()
	if cfg.Allow0RTT {
		t.Fatal("expected Allow0RTT to be false")
	}
	if cfg.MaxIdleTimeout != 30*time.Second {
		t.Fatalf("expected MaxIdleTimeout 30s, got %v", cfg.MaxIdleTimeout)
	}
	if cfg.KeepAlivePeriod != 12*time.Second {
		t.Fatalf("expected KeepAlivePeriod 12s, got %v", cfg.KeepAlivePeriod)
	}
	if !cfg.EnableDatagrams {
		t.Fatal("expected EnableDatagrams to be true")
	}
}

func TestQUICConnContextRateLimiterAndGracefulShutdown(t *testing.T) {
	cert, err := generateSelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	// Rate limiter allows strictly 1 connection per IP
	rl := NewRateLimiter(1)
	v := NewValidator()
	qs := NewQUICServer(v, nil, nil, nil, rl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := StartQUIC("127.0.0.1:0", tlsCfg, qs, ctx)
	if err != nil {
		t.Fatalf("StartQUIC failed: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	clientQUIC := &quic.Config{
		MaxIdleTimeout: 5 * time.Second,
	}

	// 1. First connection should succeed
	dialCtx1, cancel1 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel1()
	conn1, err := quic.DialAddr(dialCtx1, serverAddr, clientTLS, clientQUIC)
	if err != nil {
		t.Fatalf("expected first connection to succeed, got: %v", err)
	}
	defer conn1.CloseWithError(0, "normal")

	// 2. Second connection from same IP should be rejected by ConnContext rateLimiter
	dialCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_, err = quic.DialAddr(dialCtx2, serverAddr, clientTLS, clientQUIC)
	if err == nil {
		t.Fatal("expected second connection to be rejected by rate limiter, but dial succeeded")
	}

	// 3. Test graceful shutdown via context cancellation
	cancel()
	time.Sleep(50 * time.Millisecond)

	// After cancellation, dial must fail
	dialCtx3, cancel3 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel3()
	_, err = quic.DialAddr(dialCtx3, serverAddr, clientTLS, clientQUIC)
	if err == nil {
		t.Fatal("expected dial to fail after server context cancellation")
	}
}

func TestUDPRegisterLRUEviction(t *testing.T) {
	cert, err := generateSelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	v := NewValidator()
	token := "tok_lru_test_001"
	v.AddToken(token, "user", 1*time.Hour)

	qs := NewQUICServer(v, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := StartQUIC("127.0.0.1:0", tlsCfg, qs, ctx)
	if err != nil {
		t.Fatalf("StartQUIC failed: %v", err)
	}
	defer ln.Close()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	clientQUIC := &quic.Config{
		MaxIdleTimeout: 10 * time.Second,
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := quic.DialAddr(dialCtx, ln.Addr().String(), clientTLS, clientQUIC)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.CloseWithError(0, "normal")

	// Helper to send UDP register stream
	registerUDP := func(ctxID uint32, isFirst bool) (*proto.ConnectResponse, error) {
		stCtx, stCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stCancel()
		stream, err := conn.OpenStreamSync(stCtx)
		if err != nil {
			return nil, err
		}
		defer stream.Close()

		req := &proto.ConnectRequest{
			Token:     token,
			Timestamp: uint64(time.Now().UnixMilli()),
			Nonce:     []byte(fmt.Sprintf("nonce_%d", ctxID)),
			Streams: []*proto.StreamSpec{
				{
					StreamId:   ctxID,
					StreamType: proto.StreamType_UDP,
					TargetHost: "1.1.1.1",
					TargetPort: 53,
				},
			},
		}
		if err := proto.WriteMessage(stream, req); err != nil {
			return nil, err
		}
		var resp proto.ConnectResponse
		if err := proto.ReadMessage(stream, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	}

	// Register 64 UDP contexts (contextID 1..64)
	for i := uint32(1); i <= 64; i++ {
		resp, err := registerUDP(i, i == 1)
		if err != nil {
			t.Fatalf("registerUDP context %d failed: %v", i, err)
		}
		if !resp.Accepted {
			t.Fatalf("registerUDP context %d was rejected: %s", i, resp.Message)
		}
		time.Sleep(1 * time.Millisecond)
	}

	// Register 65th context: triggers LRU eviction (context 1 is the oldest) and succeeds
	resp65, err := registerUDP(65, false)
	if err != nil {
		t.Fatalf("registerUDP context 65 failed: %v", err)
	}
	if !resp65.Accepted {
		t.Fatalf("expected context 65 to be accepted via LRU eviction, got rejected: %s", resp65.Message)
	}

	// Now context 1 should have been evicted; registering context 1 again should succeed!
	resp1Again, err := registerUDP(1, false)
	if err != nil {
		t.Fatalf("registerUDP context 1 again failed: %v", err)
	}
	if !resp1Again.Accepted {
		t.Fatalf("expected re-registering context 1 to succeed after previous eviction, got: %s", resp1Again.Message)
	}
}

func TestUDPReadDeadlineTimeout(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	v := NewValidator()
	qs := NewQUICServer(v, nil, nil, nil, nil)
	qc := &quicConnState{
		server:   qs,
		contexts: make(map[uint32]*udpContext),
	}
	u := &udpContext{
		id:    101,
		token: "test_tok",
		conn:  conn,
		qConn: qc,
	}
	qc.contexts[101] = u

	// Close conn to cause readLoop to exit immediately
	_ = conn.Close()

	done := make(chan struct{})
	go func() {
		u.readLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not exit after close")
	}

	if !u.closed.Load() {
		t.Fatal("expected u.closed to be true after readLoop termination")
	}
}

func TestServerGracefulShutdownContext(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-shutdown-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := ServerConfig{
		Listen:                     "127.0.0.1:18446",
		Domain:                     "localhost",
		DataDir:                    tmpDir,
		AdminKey:                   "adminkey",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	// Verify server context is active
	if srv.ctx.Err() != nil {
		t.Fatal("expected active server ctx")
	}

	// Close server and verify cancel() shuts down context
	srv.Close()
	if srv.ctx.Err() == nil {
		t.Fatal("expected server ctx to be canceled after Close()")
	}
}

func TestDNSStreamConnectResponseProtocol(t *testing.T) {
	v := NewValidator()
	token := "dns_proto_test_token"
	v.AddToken(token, "user", 1*time.Hour)

	qs := NewQUICServer(v, nil, nil, nil, nil)
	qs.DNSResolver().SetLookupFunc(func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "success.example.com" {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		}
		return nil, fmt.Errorf("mock nxdomain")
	})

	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h3"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := StartQUIC("127.0.0.1:0", tlsCfg, qs, ctx)
	if err != nil {
		t.Fatalf("StartQUIC failed: %v", err)
	}
	defer ln.Close()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	clientQUIC := &quic.Config{
		MaxIdleTimeout: 10 * time.Second,
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := quic.DialAddr(dialCtx, ln.Addr().String(), clientTLS, clientQUIC)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.CloseWithError(0, "normal")

	// 1. 测试成功解析域名路径
	t.Run("success", func(t *testing.T) {
		stCtx, stCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stCancel()
		stream, err := conn.OpenStreamSync(stCtx)
		if err != nil {
			t.Fatalf("open stream failed: %v", err)
		}
		defer stream.Close()

		req := &proto.ConnectRequest{
			Token:     token,
			Timestamp: uint64(time.Now().UnixMilli()),
			Nonce:     []byte("dns_nonce_success"),
			Streams: []*proto.StreamSpec{
				{
					StreamId:   101,
					StreamType: proto.StreamType_CONTROL,
					TargetHost: "success.example.com",
					TargetPort: 53,
				},
			},
		}
		if err := proto.WriteMessage(stream, req); err != nil {
			t.Fatalf("write request failed: %v", err)
		}

		var resp proto.ConnectResponse
		if err := proto.ReadMessage(stream, &resp); err != nil {
			t.Fatalf("read ConnectResponse failed: %v", err)
		}
		if !resp.Accepted {
			t.Fatalf("expected Accepted=true, got message: %s", resp.Message)
		}

		var ipBuf [4]byte
		if _, err := io.ReadFull(stream, ipBuf[:]); err != nil {
			t.Fatalf("read 4-byte IP failed: %v", err)
		}
		if !net.IP(ipBuf[:]).Equal(net.ParseIP("192.0.2.1").To4()) {
			t.Fatalf("expected 192.0.2.1, got %v", net.IP(ipBuf[:]))
		}
	})

	// 2. 测试解析失败路径
	t.Run("resolve_failed", func(t *testing.T) {
		stCtx, stCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stCancel()
		stream, err := conn.OpenStreamSync(stCtx)
		if err != nil {
			t.Fatalf("open stream failed: %v", err)
		}
		defer stream.Close()

		req := &proto.ConnectRequest{
			Token:     token,
			Timestamp: uint64(time.Now().UnixMilli()),
			Nonce:     []byte("dns_nonce_fail"),
			Streams: []*proto.StreamSpec{
				{
					StreamId:   102,
					StreamType: proto.StreamType_CONTROL,
					TargetHost: "fail.example.com",
					TargetPort: 53,
				},
			},
		}
		if err := proto.WriteMessage(stream, req); err != nil {
			t.Fatalf("write request failed: %v", err)
		}

		var resp proto.ConnectResponse
		if err := proto.ReadMessage(stream, &resp); err != nil {
			t.Fatalf("read ConnectResponse failed: %v", err)
		}
		if resp.Accepted {
			t.Fatalf("expected Accepted=false for unresolvable host, got Accepted=true")
		}
		if resp.Message != "dns resolve failed" {
			t.Fatalf("expected Message 'dns resolve failed', got %q", resp.Message)
		}
	})

	// 3. 测试目标 Host 为空路径
	t.Run("empty_host", func(t *testing.T) {
		stCtx, stCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stCancel()
		stream, err := conn.OpenStreamSync(stCtx)
		if err != nil {
			t.Fatalf("open stream failed: %v", err)
		}
		defer stream.Close()

		req := &proto.ConnectRequest{
			Token:     token,
			Timestamp: uint64(time.Now().UnixMilli()),
			Nonce:     []byte("dns_nonce_empty"),
			Streams: []*proto.StreamSpec{
				{
					StreamId:   103,
					StreamType: proto.StreamType_CONTROL,
					TargetHost: "",
					TargetPort: 53,
				},
			},
		}
		if err := proto.WriteMessage(stream, req); err != nil {
			t.Fatalf("write request failed: %v", err)
		}

		var resp proto.ConnectResponse
		if err := proto.ReadMessage(stream, &resp); err != nil {
			t.Fatalf("read ConnectResponse failed: %v", err)
		}
		if resp.Accepted {
			t.Fatalf("expected Accepted=false for empty host, got Accepted=true")
		}
		if resp.Message != "missing target host" {
			t.Fatalf("expected Message 'missing target host', got %q", resp.Message)
		}
	})

	t.Run("probe_aero", func(t *testing.T) {
		stCtx, stCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stCancel()
		stream, err := conn.OpenStreamSync(stCtx)
		if err != nil {
			t.Fatalf("open stream failed: %v", err)
		}
		defer stream.Close()
		req := &proto.ConnectRequest{
			Token:     token,
			Timestamp: uint64(time.Now().UnixMilli()),
			Nonce:     []byte("dns_nonce_probe"),
			Streams: []*proto.StreamSpec{
				{
					StreamId:   104,
					StreamType: proto.StreamType_CONTROL,
					TargetHost: "probe.aero",
					TargetPort: 53,
				},
			},
		}
		if err := proto.WriteMessage(stream, req); err != nil {
			t.Fatalf("write request failed: %v", err)
		}
		var resp proto.ConnectResponse
		if err := proto.ReadMessage(stream, &resp); err != nil {
			t.Fatalf("read ConnectResponse failed: %v", err)
		}
		if !resp.Accepted {
			t.Fatalf("expected Accepted=true, got %s", resp.Message)
		}
		var ipBuf [4]byte
		if _, err := io.ReadFull(stream, ipBuf[:]); err != nil {
			t.Fatalf("read 4-byte IP failed: %v", err)
		}
		if !net.IP(ipBuf[:]).Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("expected 127.0.0.1, got %v", net.IP(ipBuf[:]))
		}
	})
}

func TestRelayTCP(t *testing.T) {
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h3"},
	}

	quicCfg := DefaultQUICConfig()

	connPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer connPacket.Close()

	tr := &quic.Transport{Conn: connPacket}
	defer tr.Close()

	ln, err := tr.Listen(tlsCfg, quicCfg)
	if err != nil {
		t.Fatalf("tr.Listen failed: %v", err)
	}
	defer ln.Close()

	serverConnChan := make(chan *quic.Conn, 1)
	go func() {
		c, err := ln.Accept(context.Background())
		if err == nil {
			serverConnChan <- c
		}
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	clientQUIC := &quic.Config{
		MaxIdleTimeout: 10 * time.Second,
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	clientConn, err := quic.DialAddr(dialCtx, ln.Addr().String(), clientTLS, clientQUIC)
	if err != nil {
		t.Fatalf("quic.DialAddr failed: %v", err)
	}
	defer clientConn.CloseWithError(0, "normal")

	serverConn := <-serverConnChan

	// Open a bidirectional stream from client
	stCtx, stCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stCancel()
	clientStream, err := clientConn.OpenStreamSync(stCtx)
	if err != nil {
		t.Fatalf("OpenStreamSync failed: %v", err)
	}
	defer clientStream.Close()

	streamID := uint32(202)
	token := "test_relay_token"

	// Write initial frame so peer receives stream creation
	sendFrame := &proto.TcpFrame{
		StreamId: streamID,
		Payload:  []byte("data-from-client"),
		Sequence: 1,
	}
	if err := proto.TypedWriteMessage(clientStream, proto.MsgTypeTcpFrame, sendFrame); err != nil {
		t.Fatalf("TypedWriteMessage failed: %v", err)
	}

	accCtx, accCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer accCancel()
	serverStream, err := serverConn.AcceptStream(accCtx)
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}
	defer serverStream.Close()

	v := NewValidator()
	qs := NewQUICServer(v, nil, nil, nil, nil)
	qc := &quicConnState{
		conn:   serverConn,
		server: qs,
	}

	// Create a pipe to simulate target TCP conn
	targetConn, backendConn := net.Pipe()
	defer backendConn.Close()

	relayDone := make(chan struct{})
	go func() {
		qc.relayTCP(serverStream, targetConn, token, streamID)
		close(relayDone)
	}()

	// 1. Client -> Target relay verification:
	// relayTCP reads sendFrame from serverStream and writes payload to targetConn
	buf := make([]byte, 64)
	n, err := backendConn.Read(buf)
	if err != nil {
		t.Fatalf("backendConn.Read failed: %v", err)
	}
	if string(buf[:n]) != "data-from-client" {
		t.Fatalf("expected 'data-from-client', got %q", string(buf[:n]))
	}

	// 2. Target -> Client relay verification
	go func() {
		_, _ = backendConn.Write([]byte("data-from-backend"))
	}()

	msgType, msg, err := proto.TypedReadMessage(clientStream)
	if err != nil {
		t.Fatalf("TypedReadMessage failed: %v", err)
	}
	if msgType != proto.MsgTypeTcpFrame {
		t.Fatalf("expected MsgTypeTcpFrame, got %v", msgType)
	}
	frame := msg.(*proto.TcpFrame)
	if string(frame.Payload) != "data-from-backend" {
		t.Fatalf("expected 'data-from-backend', got %q", string(frame.Payload))
	}
	if frame.StreamId != streamID {
		t.Fatalf("expected streamId %d, got %d", streamID, frame.StreamId)
	}

	// 3. Test QUIC connection context cancellation:
	// Closing clientConn triggers cancellation of qc.conn.Context(), which must terminate relayTCP
	_ = clientConn.CloseWithError(0, "closed by test")

	select {
	case <-relayDone:
		// Succeeded: relayTCP exited promptly upon QUIC conn context cancellation
	case <-time.After(3 * time.Second):
		t.Fatal("relayTCP did not exit after QUIC conn context cancellation")
	}
}

func TestServerProductionRejectNoCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-serve-prod-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := ServerConfig{
		Listen:                     ":18448",
		Domain:                     "localhost",
		DataDir:                    tmpDir,
		AdminKey:                   "adminkey",
		AllowSelfSignedCertForTest: false,
	}

	_, err = NewServer(cfg)
	if err == nil {
		t.Fatal("expected NewServer to fail when AllowSelfSignedCertForTest is false and no cert/key provided")
	}
	if !strings.Contains(err.Error(), "strictly requires valid TLS certificate") {
		t.Fatalf("expected error containing 'strictly requires valid TLS certificate', got: %v", err)
	}
}

func TestGeoDataDirectListAndETag(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-geodata-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := ServerConfig{
		Listen:                     ":18449",
		Domain:                     "localhost",
		DataDir:                    tmpDir,
		AdminKey:                   "adminkey",
		AllowSelfSignedCertForTest: true,
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer server.Close()

	// 1. First GET /geodata/direct-list: 200 OK with ETag and rules body
	req1 := httptest.NewRequest(http.MethodGet, "/geodata/direct-list", nil)
	w1 := httptest.NewRecorder()
	server.ServeHTTP(w1, req1)

	resp1 := w1.Result()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp1.StatusCode)
	}
	if ct := resp1.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("expected text/plain Content-Type, got %q", ct)
	}
	if srv := resp1.Header.Get("Server"); srv != "nginx/1.30.5" {
		t.Fatalf("expected Server nginx/1.30.5, got %q", srv)
	}
	etag := resp1.Header.Get("ETag")
	if etag == "" {
		t.Fatal("expected non-empty ETag header")
	}
	bodyBytes1, err := io.ReadAll(resp1.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !strings.Contains(string(bodyBytes1), "baidu.com") {
		t.Fatalf("expected default rules to contain 'baidu.com', got: %s", string(bodyBytes1))
	}

	// 2. Second GET with matching If-None-Match: 304 Not Modified
	req2 := httptest.NewRequest(http.MethodGet, "/geodata/direct-list", nil)
	req2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	server.ServeHTTP(w2, req2)

	resp2 := w2.Result()
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified, got %d", resp2.StatusCode)
	}
	bodyBytes2, _ := io.ReadAll(resp2.Body)
	if len(bodyBytes2) != 0 {
		t.Fatalf("expected empty body for 304, got %d bytes", len(bodyBytes2))
	}

	// 3. GET with unquoted matching If-None-Match
	req3 := httptest.NewRequest(http.MethodGet, "/geodata/direct-list", nil)
	req3.Header.Set("If-None-Match", strings.Trim(etag, `"`))
	w3 := httptest.NewRecorder()
	server.ServeHTTP(w3, req3)

	resp3 := w3.Result()
	if resp3.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304 for unquoted ETag match, got %d", resp3.StatusCode)
	}

	// 4. GET with mismatched If-None-Match: 200 OK
	req4 := httptest.NewRequest(http.MethodGet, "/geodata/direct-list", nil)
	req4.Header.Set("If-None-Match", `"outdated-or-mismatched-etag"`)
	w4 := httptest.NewRecorder()
	server.ServeHTTP(w4, req4)

	resp4 := w4.Result()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for mismatched ETag, got %d", resp4.StatusCode)
	}

	// 5. Method not allowed for non-GET/HEAD
	req5 := httptest.NewRequest(http.MethodPost, "/geodata/direct-list", nil)
	w5 := httptest.NewRecorder()
	server.ServeHTTP(w5, req5)

	resp5 := w5.Result()
	if resp5.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", resp5.StatusCode)
	}

	// 6. HEAD /geodata/direct-list: 200 OK, empty body, ETag present
	req6 := httptest.NewRequest(http.MethodHead, "/geodata/direct-list", nil)
	w6 := httptest.NewRecorder()
	server.ServeHTTP(w6, req6)

	resp6 := w6.Result()
	if resp6.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for HEAD, got %d", resp6.StatusCode)
	}
	bodyBytes6, _ := io.ReadAll(resp6.Body)
	if len(bodyBytes6) != 0 {
		t.Fatalf("expected 0 bytes body for HEAD, got %d", len(bodyBytes6))
	}
}

func TestGeoDataDiskCacheAndCronUpdate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-geodata-cache-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Pre-populate geodata_direct.txt
	customRules := "custom.direct.domain.com\n10.0.0.0/8\n"
	cachedPath := filepath.Join(tmpDir, "geodata_direct.txt")
	if err := os.WriteFile(cachedPath, []byte(customRules), 0o644); err != nil {
		t.Fatal(err)
	}

	h := NewGeoDataHandler(tmpDir)
	if string(h.Data()) != customRules {
		t.Fatalf("expected cached rules %q, got %q", customRules, string(h.Data()))
	}
	if h.ETag() == "" {
		t.Fatal("expected non-empty ETag")
	}

	// Test mock HTTP server for fetchAndUpdate
	cronTriggered := make(chan struct{}, 10)
	updatedRules := "updated.service.cn\n20.0.0.0/8\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case cronTriggered <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(updatedRules))
	}))
	defer ts.Close()

	h.fetchURL = ts.URL
	h.httpClient = ts.Client()

	if err := h.fetchAndUpdate(); err != nil {
		t.Fatalf("fetchAndUpdate failed: %v", err)
	}

	// Verify updated in memory
	if string(h.Data()) != updatedRules {
		t.Fatalf("expected updated rules %q, got %q", updatedRules, string(h.Data()))
	}

	// Verify updated on disk
	diskContent, err := os.ReadFile(cachedPath)
	if err != nil {
		t.Fatalf("read cachedPath failed: %v", err)
	}
	if string(diskContent) != updatedRules {
		t.Fatalf("expected disk content %q, got %q", updatedRules, string(diskContent))
	}

	// Verify re-fetch of identical data is a no-op
	if err := h.fetchAndUpdate(); err != nil {
		t.Fatalf("identical fetchAndUpdate failed: %v", err)
	}

	// Drain signals from initial manual fetches
	for len(cronTriggered) > 0 {
		<-cronTriggered
	}

	// Test StartCronUpdate with configurable cronInterval and cancellation
	h.cronInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	h.StartCronUpdate(ctx)

	// Verify real Ticker periodic triggers without race conditions
	select {
	case <-cronTriggered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first cron tick")
	}

	select {
	case <-cronTriggered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second cron tick")
	}

	cancel() // should exit cleanly without hanging
}

func TestSubscriptionLineTypeAndISPAffinity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-sub-isp-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := ServerConfig{
		Listen:                     ":18450",
		Domain:                     "edge.example.com",
		DataDir:                    tmpDir,
		AdminKey:                   "adminkey",
		LineType:                   "iplc",
		ISPAffinity:                "cm",
		AllowSelfSignedCertForTest: true,
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer server.Close()

	// Check client-sub.json on disk
	clientSubPath := filepath.Join(tmpDir, "client-sub.json")
	data, err := os.ReadFile(clientSubPath)
	if err != nil {
		t.Fatalf("read client-sub.json failed: %v", err)
	}

	var doc SubDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal client-sub.json failed: %v", err)
	}

	if len(doc.Servers) == 0 {
		t.Fatal("expected at least 1 server in client-sub.json")
	}
	if doc.Servers[0].LineType != "iplc" {
		t.Fatalf("expected LineType 'iplc', got %q", doc.Servers[0].LineType)
	}
	if doc.Servers[0].ISPAffinity != "cm" {
		t.Fatalf("expected ISPAffinity 'cm', got %q", doc.Servers[0].ISPAffinity)
	}

	// Verify /sub/{secret} HTTP response
	secret := server.subStore.Secret()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+secret, nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for /sub/%s, got %d", secret, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var httpDoc SubDocument
	if err := json.Unmarshal(body, &httpDoc); err != nil {
		t.Fatalf("unmarshal HTTP sub failed: %v", err)
	}
	if len(httpDoc.Servers) == 0 {
		t.Fatal("expected servers in HTTP sub response")
	}
	if httpDoc.Servers[0].LineType != "iplc" {
		t.Fatalf("expected HTTP sub LineType 'iplc', got %q", httpDoc.Servers[0].LineType)
	}
	if httpDoc.Servers[0].ISPAffinity != "cm" {
		t.Fatalf("expected HTTP sub ISPAffinity 'cm', got %q", httpDoc.Servers[0].ISPAffinity)
	}
}

func TestUDPContextIdleReaping(t *testing.T) {
	v := NewValidator()
	cl := NewConnLimiter(100, 10)
	bl := NewBandwidthLimiter(1000000)
	dg := NewDialGuard(10)
	rl := NewRateLimiter(100)
	server := NewQUICServer(v, cl, bl, dg, rl)

	qConn := &quicConnState{
		server:   server,
		contexts: make(map[uint32]*udpContext),
	}

	token := "reaper_test_token"
	server.tokenUDPCtx[token] = 2

	now := time.Now()
	// Active context (active 1 second ago)
	activeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer activeConn.Close()

	activeCtx := &udpContext{
		id:    1,
		token: token,
		conn:  activeConn,
		qConn: qConn,
	}
	activeCtx.lastActive.Store(now.Add(-1 * time.Second).UnixNano())
	qConn.contexts[1] = activeCtx

	// Idle context (active 60 seconds ago)
	idleConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer idleConn.Close()

	idleCtx := &udpContext{
		id:    2,
		token: token,
		conn:  idleConn,
		qConn: qConn,
	}
	idleCtx.lastActive.Store(now.Add(-60 * time.Second).UnixNano())
	qConn.contexts[2] = idleCtx

	// Reap contexts idle for > 45s
	reaped := qConn.reapIdleContexts(45 * time.Second)
	if reaped != 1 {
		t.Fatalf("expected 1 reaped context, got %d", reaped)
	}

	qConn.ctxMu.RLock()
	_, activeExists := qConn.contexts[1]
	_, idleExists := qConn.contexts[2]
	qConn.ctxMu.RUnlock()

	if !activeExists {
		t.Fatal("expected active context 1 to still exist")
	}
	if idleExists {
		t.Fatal("expected idle context 2 to be removed")
	}

	server.udpMu.Lock()
	remSlots := server.tokenUDPCtx[token]
	server.udpMu.Unlock()
	if remSlots != 1 {
		t.Fatalf("expected remaining UDP slots 1, got %d", remSlots)
	}
}

func TestServeListenerContextCancel(t *testing.T) {
	v := NewValidator()
	cl := NewConnLimiter(100, 10)
	bl := NewBandwidthLimiter(1000000)
	dg := NewDialGuard(10)
	rl := NewRateLimiter(100)
	server := NewQUICServer(v, cl, bl, dg, rl)

	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h3"},
	}

	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	tr := &quic.Transport{Conn: udpConn}
	defer tr.Close()

	ln, err := tr.Listen(tlsCfg, DefaultQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeListener(ctx, ln)
	}()

	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected non-nil error when context is canceled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeListener did not return within 2s after context cancel")
	}
}
