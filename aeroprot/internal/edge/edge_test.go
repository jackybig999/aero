// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/connect-ip-go"
	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func TestDatagramFraming(t *testing.T) {
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

	// 1. Healthz endpoint test (探活端点：纯文本 ok，无硬编码 Server)
	reqHz := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recHz := httptest.NewRecorder()
	srv.ServeHTTP(recHz, reqHz)
	if recHz.Code != http.StatusOK {
		t.Fatalf("healthz expected 200, got %d", recHz.Code)
	}
	if recHz.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("expected Content-Type 'text/plain; charset=utf-8', got %q", recHz.Header().Get("Content-Type"))
	}
	if recHz.Body.String() != "ok" {
		t.Fatalf("expected body 'ok', got %q", recHz.Body.String())
	}
	if recHz.Header().Get("Server") != "" {
		t.Fatalf("expected empty Server header, got %q", recHz.Header().Get("Server"))
	}
	if recHz.Header().Get("Alt-Svc") != `h3=":443"; ma=86400` {
		t.Fatalf("expected Alt-Svc 'h3=\":443\"; ma=86400', got %q", recHz.Header().Get("Alt-Svc"))
	}

	// 2. Health endpoint test (管理面 JSON)
	reqH := httptest.NewRequest(http.MethodGet, "/health", nil)
	recH := httptest.NewRecorder()
	srv.ServeHTTP(recH, reqH)
	if recH.Code != http.StatusOK {
		t.Fatalf("health expected 200, got %d", recH.Code)
	}
	if recH.Header().Get("Server") != "" {
		t.Fatalf("expected empty Server header, got %q", recH.Header().Get("Server"))
	}
	if recH.Header().Get("Alt-Svc") != `h3=":443"; ma=86400` {
		t.Fatalf("expected Alt-Svc 'h3=\":443\"; ma=86400', got %q", recH.Header().Get("Alt-Svc"))
	}

	// 3. Cover site endpoint test (返回嵌入的 cover.html)
	reqC := httptest.NewRequest(http.MethodGet, "/", nil)
	recC := httptest.NewRecorder()
	srv.ServeHTTP(recC, reqC)
	if recC.Code != http.StatusOK {
		t.Fatalf("cover expected 200, got %d", recC.Code)
	}
	if recC.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type 'text/html; charset=utf-8', got %q", recC.Header().Get("Content-Type"))
	}
	if recC.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("expected Cache-Control 'public, max-age=3600', got %q", recC.Header().Get("Cache-Control"))
	}
	if recC.Header().Get("Server") != "" {
		t.Fatalf("expected empty Server header, got %q", recC.Header().Get("Server"))
	}
	if recC.Header().Get("Alt-Svc") != `h3=":443"; ma=86400` {
		t.Fatalf("expected Alt-Svc 'h3=\":443\"; ma=86400', got %q", recC.Header().Get("Alt-Svc"))
	}
	if !strings.Contains(recC.Body.String(), "AERO Edge Cloud") {
		t.Fatalf("cover page missing expected text 'AERO Edge Cloud'")
	}

	// 4. Asset endpoint test (返回嵌入的 cover.css)
	reqA := httptest.NewRequest(http.MethodGet, "/assets/style.css", nil)
	recA := httptest.NewRecorder()
	srv.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("assets expected 200, got %d", recA.Code)
	}
	if recA.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("expected Content-Type 'text/css; charset=utf-8', got %q", recA.Header().Get("Content-Type"))
	}
	if recA.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("expected Cache-Control 'public, max-age=3600', got %q", recA.Header().Get("Cache-Control"))
	}
	if !strings.Contains(recA.Body.String(), "--bg-primary") {
		t.Fatalf("cover css missing expected styling variables")
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

	// 2. Verify all HTTP endpoints do not return hardcoded Server: nginx and retain Alt-Svc
	endpoints := []string{"/", "/healthz", "/health", "/assets/style.css", "/admin/version", "/sub/nonexistent"}
	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		serverHeader := rec.Header().Get("Server")
		if serverHeader != "" {
			t.Fatalf("endpoint %s expected empty Server header (no hardcoded nginx), got %q", ep, serverHeader)
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
	if cfg.MaxIdleTimeout != 90*time.Second {
		t.Fatalf("expected MaxIdleTimeout 90s, got %v", cfg.MaxIdleTimeout)
	}
	if cfg.KeepAlivePeriod != 10*time.Second {
		t.Fatalf("expected KeepAlivePeriod 10s, got %v", cfg.KeepAlivePeriod)
	}
	if !cfg.EnableDatagrams {
		t.Fatal("expected EnableDatagrams to be true")
	}
}

func TestDefaultQUICConfigPacketSizeAnd0RTT(t *testing.T) {
	cfg := DefaultQUICConfig()
	if cfg.InitialPacketSize != 0 {
		t.Fatalf("expected DefaultQUICConfig().InitialPacketSize == 0, got %d", cfg.InitialPacketSize)
	}
	if cfg.Allow0RTT != false {
		t.Fatalf("expected DefaultQUICConfig().Allow0RTT == false, got %v", cfg.Allow0RTT)
	}
}

func findTestAddr() (string, string) {
	// First probe IPv4 127.0.0.1 loopback
	s, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err == nil {
		c, err2 := net.ListenPacket("udp4", "127.0.0.1:0")
		if err2 == nil {
			_, writeErr := c.WriteTo([]byte("ping"), s.LocalAddr())
			_ = s.Close()
			_ = c.Close()
			if writeErr == nil {
				return "127.0.0.1:0", "localhost"
			}
		} else {
			_ = s.Close()
		}
	}
	// Fallback to IPv6 loopback [::1] (bypasses Windows Filtering Platform WFP loopback interception)
	s6, err := net.ListenPacket("udp6", "[::1]:0")
	if err == nil {
		_ = s6.Close()
		return "[::1]:0", "localhost"
	}
	return "127.0.0.1:0", "localhost"
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func testDialQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
	network := "udp4"
	bindAddr := "127.0.0.1:0"
	if strings.Contains(addr, "[") || strings.HasPrefix(addr, "::") {
		network = "udp6"
		bindAddr = "[::1]:0"
	}
	pconn, err := net.ListenPacket(network, bindAddr)
	if err != nil {
		return nil, err
	}
	rAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}
	tr := &quic.Transport{Conn: pconn}
	conn, err := tr.Dial(ctx, rAddr, tlsCfg, quicCfg)
	if err != nil {
		_ = tr.Close()
		_ = pconn.Close()
		return nil, err
	}
	go func() {
		<-conn.Context().Done()
		_ = tr.Close()
		_ = pconn.Close()
	}()
	return conn, nil
}

func TestQUICConnContextRateLimiterAndGracefulShutdown(t *testing.T) {
	listenAddr, host := findTestAddr()
	cert, err := generateSelfSignedCert(host)
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

	ln, err := StartQUIC(listenAddr, tlsCfg, qs, ctx)
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
	conn1, err := testDialQUIC(dialCtx1, serverAddr, clientTLS, clientQUIC)
	if err != nil {
		t.Fatalf("expected first connection to succeed, got: %v", err)
	}
	defer conn1.CloseWithError(0, "normal")

	// 2. Second connection from same IP should be rejected by ConnContext rateLimiter
	dialCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_, err = testDialQUIC(dialCtx2, serverAddr, clientTLS, clientQUIC)
	if err == nil {
		t.Fatal("expected second connection to be rejected by rate limiter, but dial succeeded")
	}

	// 3. Test graceful shutdown via context cancellation
	cancel()
	time.Sleep(50 * time.Millisecond)

	// After cancellation, dial must fail
	dialCtx3, cancel3 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel3()
	_, err = testDialQUIC(dialCtx3, serverAddr, clientTLS, clientQUIC)
	if err == nil {
		t.Fatal("expected dial to fail after server context cancellation")
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
	if srv := resp1.Header.Get("Server"); srv != "" {
		t.Fatalf("expected empty Server header, got %q", srv)
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

	// Test mock HTTP client for fetchAndUpdate
	cronTriggered := make(chan struct{}, 10)
	updatedRules := "updated.service.cn\n20.0.0.0/8\n"

	h.fetchURL = "http://mock-geodata.aero.internal/rules.txt"
	h.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			select {
			case cronTriggered <- struct{}{}:
			default:
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(strings.NewReader(updatedRules)),
			}, nil
		}),
	}

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

func TestStartQUICWithQlogDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aero-qlog-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origQlogDir := os.Getenv("AERO_QLOG_DIR")
	defer func() {
		_ = os.Setenv("AERO_QLOG_DIR", origQlogDir)
	}()
	_ = os.Setenv("AERO_QLOG_DIR", tmpDir)

	listenAddr, host := findTestAddr()
	cert, err := generateSelfSignedCert(host)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	qs := NewQUICServer(NewValidator(), nil, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := StartQUIC(listenAddr, tlsCfg, qs, ctx)
	if err != nil {
		t.Fatalf("StartQUIC with AERO_QLOG_DIR failed: %v", err)
	}
	defer ln.Close()

	if os.Getenv("QLOGDIR") != tmpDir {
		t.Fatalf("expected QLOGDIR to be set to %s, got %s", tmpDir, os.Getenv("QLOGDIR"))
	}
}

// TestHopCredentialRequired (P7 规范验证)
// 当 Role 为 ingress 或 egress 时，必须配置跳间凭证 HopCredential；
// 若凭证为空，启动直接失败，错误文本必须包含 "hop credential required"。
func TestHopCredentialRequired(t *testing.T) {
	dataDir := t.TempDir()

	// 1. Role = ingress，空凭证：必须失败，错误含 "hop credential required"
	cfgIngress := ServerConfig{
		Listen:                     "127.0.0.1:0",
		Domain:                     "localhost",
		DataDir:                    dataDir,
		Role:                       "ingress",
		HopCredential:              "",
		AllowSelfSignedCertForTest: true,
	}
	_, errIngress := NewServer(cfgIngress)
	if errIngress == nil {
		t.Fatal("expected NewServer with role=ingress and empty hop credential to fail, got nil")
	}
	if !strings.Contains(errIngress.Error(), "hop credential required") {
		t.Fatalf("expected error to contain 'hop credential required', got: %v", errIngress)
	}

	// 2. Role = egress，空凭证：必须失败，错误含 "hop credential required"
	cfgEgress := ServerConfig{
		Listen:                     "127.0.0.1:0",
		Domain:                     "localhost",
		DataDir:                    dataDir,
		Role:                       "egress",
		HopCredential:              "   ",
		AllowSelfSignedCertForTest: true,
	}
	_, errEgress := NewServer(cfgEgress)
	if errEgress == nil {
		t.Fatal("expected NewServer with role=egress and empty hop credential to fail, got nil")
	}
	if !strings.Contains(errEgress.Error(), "hop credential required") {
		t.Fatalf("expected error to contain 'hop credential required', got: %v", errEgress)
	}

	// 3. 配置了非空跳间凭证时：创建成功
	cfgValid := ServerConfig{
		Listen:                     "127.0.0.1:0",
		Domain:                     "localhost",
		DataDir:                    dataDir,
		Role:                       "ingress",
		HopCredential:              "secret-hop-credential-xyz",
		AllowSelfSignedCertForTest: true,
	}
	srv, errValid := NewServer(cfgValid)
	if errValid != nil {
		t.Fatalf("expected NewServer to succeed with valid hop credential, got: %v", errValid)
	}
	if srv.cfg.Role != "ingress" || srv.cfg.HopCredential != "secret-hop-credential-xyz" {
		t.Fatalf("unexpected role or hop credential in srv: role=%s, cred=%s", srv.cfg.Role, srv.cfg.HopCredential)
	}
}

// TestECHDisabledByDefault (P7 规范验证)
// 未配 ECH 或不满足三项硬性条件时，服务按普通 TLS 1.3 启动，启动成功且日志明确打印 "ECH disabled"。
func TestECHDisabledByDefault(t *testing.T) {
	dataDir := t.TempDir()

	listenAddr, host := findTestAddr()
	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Role:                       "single",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// 捕获日志输出
	var logBuf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOutput)

	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start() failed: %v", err)
	}
	defer func() {
		if srv.tcpListener != nil {
			_ = srv.tcpListener.Close()
		}
		if srv.quicListener != nil {
			_ = srv.quicListener.Close()
		}
		srv.cancel()
	}()

	logText := logBuf.String()
	if !strings.Contains(logText, "ECH disabled") {
		t.Fatalf("expected log to contain 'ECH disabled', got:\n%s", logText)
	}
}

// ==========================================
// P2/P3 HTTP/3 MASQUE Integration Tests
// ==========================================

func TestHTTP3BearerAuth(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "valid_bearer_token_123",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)

	// 1. Missing Bearer -> 401 Unauthorized, with WWW-Authenticate and Proxy-Status
	req1, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	req1.Header.Set("Content-Type", "application/dns-message")

	resp1, err := h3Conn.RoundTrip(req1)
	if err != nil {
		t.Fatalf("RoundTrip 1 failed: %v", err)
	}
	_ = resp1.Body.Close()

	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", resp1.StatusCode)
	}
	if !strings.Contains(resp1.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("expected WWW-Authenticate: Bearer, got %q", resp1.Header.Get("WWW-Authenticate"))
	}
	if !strings.Contains(resp1.Header.Get("Proxy-Status"), "proxy_authorization_required") {
		t.Fatalf("expected Proxy-Status proxy_authorization_required, got %q", resp1.Header.Get("Proxy-Status"))
	}

	// Verify connection remains ALIVE and not closed!
	if qConn.Context().Err() != nil {
		t.Fatalf("connection was closed after 401: %v", qConn.Context().Err())
	}

	// 2. First request with Bearer + Aero-Timestamp + Aero-Nonce -> succeeds (e.g. 400 bad DNS packet or 200, not 401)
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/dns-message")
	req2.Header.Set("Authorization", "Bearer valid_bearer_token_123")
	req2.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req2.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	resp2, err := h3Conn.RoundTrip(req2)
	if err != nil {
		t.Fatalf("RoundTrip 2 failed: %v", err)
	}
	_ = resp2.Body.Close()

	if resp2.StatusCode == http.StatusUnauthorized {
		t.Fatalf("expected authorization success, got 401")
	}

	// 3. Subsequent request on same connection: only Bearer header, NO timestamp or nonce -> succeeds!
	req3, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	req3.Header.Set("Content-Type", "application/dns-message")
	req3.Header.Set("Authorization", "Bearer valid_bearer_token_123")

	resp3, err := h3Conn.RoundTrip(req3)
	if err != nil {
		t.Fatalf("RoundTrip 3 failed: %v", err)
	}
	_ = resp3.Body.Close()

	if resp3.StatusCode == http.StatusUnauthorized {
		t.Fatalf("expected subsequent request authorization to succeed, got 401")
	}

	// 4. Request with wrong token on same connection -> 401
	req4, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	req4.Header.Set("Content-Type", "application/dns-message")
	req4.Header.Set("Authorization", "Bearer wrong_token")

	resp4, err := h3Conn.RoundTrip(req4)
	if err != nil {
		t.Fatalf("RoundTrip 4 failed: %v", err)
	}
	_ = resp4.Body.Close()

	if resp4.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d", resp4.StatusCode)
	}
}

func TestHTTP3StandardConnect(t *testing.T) {
	listenAddr, host := findTestAddr()

	// 1. Local TCP Echo server
	tcpLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Edge server
	dataDir := t.TempDir()
	edgeAddr, _ := findTestAddr()
	cfg := ServerConfig{
		Listen:                     edgeAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "connect_test_token",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	// 3. Dial HTTP/3 connection
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)

	// 4. Standard CONNECT request
	target := tcpLn.Addr().String()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "HTTP/1.1"
	req.Header.Set("Authorization", "Bearer connect_test_token")
	req.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	reqStr, err := h3Conn.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("OpenRequestStream failed: %v", err)
	}
	defer reqStr.Close()

	if err := reqStr.SendRequestHeader(req); err != nil {
		t.Fatalf("SendRequestHeader failed: %v", err)
	}

	resp, err := reqStr.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for standard CONNECT, got %d", resp.StatusCode)
	}

	// 5. Test stream echo
	testPayload := []byte("hello aero standard connect h3")
	if _, err := reqStr.Write(testPayload); err != nil {
		t.Fatalf("write payload failed: %v", err)
	}

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(reqStr, buf); err != nil {
		t.Fatalf("read echo failed: %v", err)
	}
	if !bytes.Equal(buf, testPayload) {
		t.Fatalf("expected %q, got %q", testPayload, buf)
	}
}

func TestMASQUEConnectUDP(t *testing.T) {
	listenAddr, host := findTestAddr()

	// 1. Local UDP Echo server
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, rAddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpConn.WriteTo(buf[:n], rAddr)
		}
	}()

	// 2. Edge server
	dataDir := t.TempDir()
	edgeAddr, _ := findTestAddr()
	cfg := ServerConfig{
		Listen:                     edgeAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "masque_udp_token",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	// 3. Dial HTTP/3 + MASQUE
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)
	masqueConn := masque.NewClientConn(h3Conn)

	target := udpConn.LocalAddr().String()
	tmpl := uritemplate.MustNew("https://" + host + "/.well-known/masque/udp/{target_host}/{target_port}/")
	mReq, err := masque.NewRequest(ctx, tmpl, target)
	if err != nil {
		t.Fatalf("masque.NewRequest failed: %v", err)
	}
	mReq.Header().Set("Authorization", "Bearer masque_udp_token")
	mReq.Header().Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	mReq.Header().Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	mConn, resp, err := masqueConn.Dial(mReq)
	if err != nil {
		t.Fatalf("masqueConn.Dial failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect-udp rejected: %d %s", resp.StatusCode, resp.Status)
	}
	defer mConn.Close()

	// 4. Send datagram and verify echo
	testData := []byte("hello masque connect-udp datagram")
	rUdpAddr, _ := net.ResolveUDPAddr("udp", target)
	if _, err := mConn.WriteTo(testData, rUdpAddr); err != nil {
		t.Fatalf("mConn.WriteTo failed: %v", err)
	}

	recvBuf := make([]byte, 2048)
	_ = mConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := mConn.ReadFrom(recvBuf)
	if err != nil {
		t.Fatalf("mConn.ReadFrom failed: %v", err)
	}
	if !bytes.Equal(recvBuf[:n], testData) {
		t.Fatalf("expected %q, got %q", testData, recvBuf[:n])
	}
}

func TestCONNECTIPRoundtrip(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "connect_ip_token",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)
	connectIPClient := connectip.NewClientConn(h3Conn)

	tmpl := uritemplate.MustNew("https://" + host + "/.well-known/masque/ip/*/*/")
	ipReq, err := connectip.NewRequest(ctx, tmpl)
	if err != nil {
		t.Fatalf("connectip.NewRequest failed: %v", err)
	}
	ipReq.Header().Set("Authorization", "Bearer connect_ip_token")
	ipReq.Header().Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	ipReq.Header().Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	ipConn, resp, err := connectIPClient.Dial(ipReq)
	if err != nil {
		t.Fatalf("connectIPClient.Dial failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect-ip rejected: %d %s", resp.StatusCode, resp.Status)
	}
	defer ipConn.Close()

	// Verify assigned IP addresses from 10.88.0.0/16
	assigned, err := ipConn.ReceiveAddressAssignment(ctx)
	if err != nil {
		t.Fatalf("ReceiveAddressAssignment failed: %v", err)
	}
	if len(assigned) == 0 {
		t.Fatal("expected at least 1 assigned prefix")
	}
	assignedIP := assigned[0].IPPrefix.Addr()
	if !strings.HasPrefix(assignedIP.String(), "10.88.") {
		t.Fatalf("expected assigned IP in 10.88.0.0/16, got %s", assignedIP.String())
	}

	// Build ICMP Echo Request packet
	clientIPBytes := assignedIP.As4()
	serverIPBytes := [4]byte{10, 88, 0, 1}

	icmpReq := make([]byte, 28) // 20-byte IPv4 + 8-byte ICMP
	icmpReq[0] = 0x45
	binary.BigEndian.PutUint16(icmpReq[2:4], 28)
	icmpReq[8] = 64
	icmpReq[9] = 1 // ICMP
	copy(icmpReq[12:16], clientIPBytes[:])
	copy(icmpReq[16:20], serverIPBytes[:])
	ipChk := calcChecksum(icmpReq[:20])
	binary.BigEndian.PutUint16(icmpReq[10:12], ipChk)

	icmpReq[20] = 8 // Echo Request
	icmpReq[21] = 0
	binary.BigEndian.PutUint16(icmpReq[24:26], 1) // ID
	binary.BigEndian.PutUint16(icmpReq[26:28], 1) // Seq
	icmpChk := calcChecksum(icmpReq[20:])
	binary.BigEndian.PutUint16(icmpReq[22:24], icmpChk)

	if _, err := ipConn.WritePacket(icmpReq); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	replyBuf := make([]byte, 1500)
	n, err := ipConn.ReadPacket(replyBuf)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}
	if n < 28 {
		t.Fatalf("expected at least 28 bytes in reply, got %d", n)
	}
	// Verify ICMP Echo Reply (Type 0)
	if replyBuf[20] != 0 {
		t.Fatalf("expected ICMP Echo Reply (type 0), got type %d", replyBuf[20])
	}
}

func TestDoHResolution(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "doh_token",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)

	// 1. A Record query for "localhost"
	dnsAQuery := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // standard query
		0x00, 0x01, // 1 question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	dnsAQuery = append(dnsAQuery, encodeDNSName("localhost")...)
	dnsAQuery = append(dnsAQuery, 0x00, 0x01, 0x00, 0x01) // A IN

	reqA, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader(dnsAQuery))
	if err != nil {
		t.Fatal(err)
	}
	reqA.Header.Set("Content-Type", "application/dns-message")
	reqA.Header.Set("Authorization", "Bearer doh_token")
	reqA.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	reqA.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	respA, err := h3Conn.RoundTrip(reqA)
	if err != nil {
		t.Fatalf("RoundTrip A query failed: %v", err)
	}
	bodyA, err := io.ReadAll(respA.Body)
	_ = respA.Body.Close()
	if err != nil {
		t.Fatalf("read bodyA failed: %v", err)
	}
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for DoH query, got %d", respA.StatusCode)
	}
	if len(bodyA) < 12 {
		t.Fatalf("invalid DNS response length: %d", len(bodyA))
	}
	// Verify transaction ID matches
	if bodyA[0] != 0x12 || bodyA[1] != 0x34 {
		t.Fatalf("expected transaction ID 0x1234, got %02x%02x", bodyA[0], bodyA[1])
	}

	// 2. AAAA Record query -> Empty answer
	dnsAAAAQuery := []byte{
		0x56, 0x78, // ID
		0x01, 0x00, // standard query
		0x00, 0x01, // 1 question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	dnsAAAAQuery = append(dnsAAAAQuery, encodeDNSName("localhost")...)
	dnsAAAAQuery = append(dnsAAAAQuery, 0x00, 0x1C, 0x00, 0x01) // AAAA IN

	reqAAAA, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader(dnsAAAAQuery))
	if err != nil {
		t.Fatal(err)
	}
	reqAAAA.Header.Set("Content-Type", "application/dns-message")
	reqAAAA.Header.Set("Authorization", "Bearer doh_token")

	respAAAA, err := h3Conn.RoundTrip(reqAAAA)
	if err != nil {
		t.Fatalf("RoundTrip AAAA query failed: %v", err)
	}
	bodyAAAA, err := io.ReadAll(respAAAA.Body)
	_ = respAAAA.Body.Close()
	if err != nil {
		t.Fatalf("read bodyAAAA failed: %v", err)
	}
	if respAAAA.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for AAAA query, got %d", respAAAA.StatusCode)
	}
	// Verify Answer count == 0 in flags
	ancount := binary.BigEndian.Uint16(bodyAAAA[6:8])
	if ancount != 0 {
		t.Fatalf("expected 0 answers for AAAA, got %d", ancount)
	}
}

func TestHTTP3Healthz(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "healthz_token",
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{}
	h3Conn := tr.NewClientConn(qConn)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := h3Conn.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip /healthz failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("expected 'ok', got %q", string(body))
	}
}
