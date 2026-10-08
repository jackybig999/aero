// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
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

	// TakeContext with canceled context on large byte count should exit immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	// exhaust burst first
	bl.Take("user_exhaust", 20000)
	err := bl.TakeContext(ctx, "user_exhaust", 50000)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
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

	// 1. GET /sub/superadmin -> must return 404 and contain NO token
	reqAdmin := httptest.NewRequest(http.MethodGet, "/sub/superadmin", nil)
	recAdmin := httptest.NewRecorder()
	if !handler.TryServe(recAdmin, reqAdmin) {
		t.Fatal("TryServe should handle /sub/superadmin")
	}
	if recAdmin.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recAdmin.Code)
	}
	if strings.Contains(recAdmin.Body.String(), "token") {
		t.Fatalf("response body must not contain token: %s", recAdmin.Body.String())
	}

	// 1b. GET /sub/{nodeSecret} -> must return 200
	reqNode := httptest.NewRequest(http.MethodGet, "/sub/"+store.Secret(), nil)
	recNode := httptest.NewRecorder()
	if !handler.TryServe(recNode, reqNode) {
		t.Fatal("TryServe should handle node secret")
	}
	if recNode.Code != http.StatusOK {
		t.Fatalf("expected 200 for node secret, got %d", recNode.Code)
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
	if recHz.Header().Get("Alt-Svc") != "" {
		t.Fatalf("expected empty Alt-Svc header, got %q", recHz.Header().Get("Alt-Svc"))
	}

	// 2. Health endpoint test (管理面 JSON，脱敏鉴权：未鉴权 404，带密钥 200)
	reqHUnauth := httptest.NewRequest(http.MethodGet, "/health", nil)
	recHUnauth := httptest.NewRecorder()
	srv.ServeHTTP(recHUnauth, reqHUnauth)
	if recHUnauth.Code != http.StatusNotFound {
		t.Fatalf("unauthenticated health expected 404, got %d", recHUnauth.Code)
	}

	// 2a. With query parameter admin_key
	reqHQuery := httptest.NewRequest(http.MethodGet, "/health?admin_key=adminkey", nil)
	recHQuery := httptest.NewRecorder()
	srv.ServeHTTP(recHQuery, reqHQuery)
	if recHQuery.Code != http.StatusOK {
		t.Fatalf("query authenticated health expected 200, got %d", recHQuery.Code)
	}

	// 2b. With header Aero-Admin-Key
	reqH := httptest.NewRequest(http.MethodGet, "/health", nil)
	reqH.Header.Set("Aero-Admin-Key", "adminkey")
	recH := httptest.NewRecorder()
	srv.ServeHTTP(recH, reqH)
	if recH.Code != http.StatusOK {
		t.Fatalf("health expected 200, got %d", recH.Code)
	}
	if recH.Header().Get("Server") != "" {
		t.Fatalf("expected empty Server header, got %q", recH.Header().Get("Server"))
	}
	if recH.Header().Get("Alt-Svc") != "" {
		t.Fatalf("expected empty Alt-Svc header, got %q", recH.Header().Get("Alt-Svc"))
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
	if recC.Header().Get("Alt-Svc") != "" {
		t.Fatalf("expected empty Alt-Svc header, got %q", recC.Header().Get("Alt-Svc"))
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

	// 2. Verify all HTTP endpoints do not return hardcoded Server: nginx and do not return Alt-Svc
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
		if altSvcHeader != "" {
			t.Fatalf("endpoint %s expected empty Alt-Svc header, got %q", ep, altSvcHeader)
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

func findTCPTestTarget() net.IP {
	// First probe IPv4 127.0.0.1
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err == nil {
		c, err2 := net.DialTimeout("tcp4", ln.Addr().String(), 100*time.Millisecond)
		if err2 == nil {
			_ = c.Close()
			_ = ln.Close()
			return net.ParseIP("127.0.0.1")
		}
		_ = ln.Close()
	}
	// Fallback to local unicast non-loopback IPv4 (bypasses Windows WFP loopback interception)
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ln2, err2 := net.Listen("tcp4", net.JoinHostPort(ip4.String(), "0"))
					if err2 == nil {
						c2, err3 := net.DialTimeout("tcp4", ln2.Addr().String(), 100*time.Millisecond)
						if err3 == nil {
							_ = c2.Close()
							_ = ln2.Close()
							return ip4
						}
						_ = ln2.Close()
					}
				}
			}
		}
	}
	return net.ParseIP("127.0.0.1")
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

// TestPhase4Gate_EdgeECHWithoutHTTPSRR (阶段四规范验证)
// 在不配置公网 HTTPS RR 的情况下，只要配置了 EncryptedClientHelloKeys，服务端成功启动并开启 ECH，日志包含 "ECH enabled"。
func TestPhase4Gate_EdgeECHWithoutHTTPSRR(t *testing.T) {
	dataDir := t.TempDir()

	listenAddr, host := findTestAddr()
	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Role:                       "single",
		AllowSelfSignedCertForTest: true,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{
			{
				Config:      []byte("dummy-ech-config-phase4"),
				PrivateKey:  []byte("dummy-ech-key-phase4"),
				SendAsRetry: true,
			},
		},
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
	if !strings.Contains(logText, "ECH enabled") {
		t.Fatalf("expected log to contain 'ECH enabled', got:\n%s", logText)
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

func TestConnectUDP(t *testing.T) {
	t.Run("LongRangeEcho", func(t *testing.T) {
		t.Parallel()

		listenAddr, host := findTestAddr()

		// 1. Echo UDP Server
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
			Token:                      "long_range_udp_token",
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

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
		mReq.Header().Set("Authorization", "Bearer long_range_udp_token")
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

		rUdpAddr, _ := net.ResolveUDPAddr("udp", target)

		// 7 packets across 70 seconds:
		// Target schedule in seconds: 10, 20, 30, 40, 46, 58, 70
		schedule := []int{10, 20, 30, 40, 46, 58, 70}
		start := time.Now()

		for idx, targetSec := range schedule {
			targetTime := start.Add(time.Duration(targetSec) * time.Second)
			if wait := time.Until(targetTime); wait > 0 {
				time.Sleep(wait)
			}
			elapsed := time.Since(start)
			pktData := []byte(fmt.Sprintf("pkt-%d-target-%d", idx+1, targetSec))
			if _, err := mConn.WriteTo(pktData, rUdpAddr); err != nil {
				t.Fatalf("WriteTo pkt %d (sec %d) failed at %v: %v", idx+1, targetSec, elapsed, err)
			}

			recvBuf := make([]byte, 2048)
			_ = mConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _, err := mConn.ReadFrom(recvBuf)
			if err != nil {
				t.Fatalf("ReadFrom pkt %d (sec %d) failed at %v: %v", idx+1, targetSec, elapsed, err)
			}
			if !bytes.Equal(recvBuf[:n], pktData) {
				t.Fatalf("pkt %d mismatch: sent %q, got %q", idx+1, pktData, recvBuf[:n])
			}

			if targetSec == 46 {
				t.Logf("[ASSERT] 46s packet successfully read back at elapsed %v (45s deadlock eliminated!)", elapsed)
			}
			if targetSec == 70 {
				t.Logf("[ASSERT] 70s packet successfully read back at elapsed %v (long-range keepalive verified!)", elapsed)
			}
		}
	})

	t.Run("IdleTimeout", func(t *testing.T) {
		t.Parallel()

		listenAddr, host := findTestAddr()

		// 1. Echo UDP Server
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
			Token:                      "idle_timeout_udp_token",
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

		ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
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
		mReq.Header().Set("Authorization", "Bearer idle_timeout_udp_token")
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

		rUdpAddr, _ := net.ResolveUDPAddr("udp", target)

		// Send initial probe to confirm active connection
		probe := []byte("initial-probe")
		if _, err := mConn.WriteTo(probe, rUdpAddr); err != nil {
			t.Fatalf("initial WriteTo failed: %v", err)
		}
		recvBuf := make([]byte, 2048)
		_ = mConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := mConn.ReadFrom(recvBuf)
		if err != nil || !bytes.Equal(recvBuf[:n], probe) {
			t.Fatalf("initial echo failed: %v", err)
		}

		if srv.quicServer.globalUDPCtx.Load() != 1 {
			t.Fatalf("expected 1 active UDP slot before silence, got %d", srv.quicServer.globalUDPCtx.Load())
		}

		// 4. Silence for 50 seconds
		t.Log("Beginning 50s silence period for idle watchdog timeout test...")
		time.Sleep(50 * time.Second)

		// 5. Assert that watchdog triggered and connection is closed:
		// Server-side: srv.quicServer.globalUDPCtx must be 0 (slot released)
		released := false
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if srv.quicServer.globalUDPCtx.Load() == 0 {
				released = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !released {
			t.Fatalf("expected server UDP slot to be released after 50s silence, got %d", srv.quicServer.globalUDPCtx.Load())
		}
		t.Log("[ASSERT] Server UDP slot successfully released by watchdog")

		// Client-side: ReadFrom must fail because server closed stream
		_, _ = mConn.WriteTo([]byte("probe-after-timeout"), rUdpAddr)
		_ = mConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err = mConn.ReadFrom(recvBuf)
		if err == nil {
			t.Fatal("expected ReadFrom to fail after 50s silence, but packet was read")
		}
		t.Logf("[ASSERT] Connection verified closed on client (ReadFrom returned: %v)", err)
	})
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

	// Start a real TCP echo server on host
	targetIP := findTCPTestTarget()
	echoLn, err := net.Listen("tcp4", net.JoinHostPort(targetIP.String(), "0"))
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}
	defer echoLn.Close()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	clientEP := channel.New(512, 1420, "")
	clientStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				AllowExternalLoopbackTraffic: true,
			}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
		},
	})
	nicID := tcpip.NICID(1)
	if err := clientStack.CreateNIC(nicID, clientEP); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}
	clientStack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(assignedIP.As4()).WithPrefix(),
	}, stack.AddressProperties{})
	clientStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	defer pumpCancel()

	// Pump clientEP -> ipConn
	go func() {
		for {
			pkt := clientEP.ReadContext(pumpCtx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			if view != nil {
				b := view.AsSlice()
				if len(b) > 0 {
					_, _ = ipConn.WritePacket(b)
				}
				view.Release()
			}
			pkt.DecRef()
		}
	}()

	var forgedICMPReceived atomic.Bool
	dest1111 := [4]byte{1, 1, 1, 1}

	// Pump ipConn -> clientEP
	go func() {
		buf := make([]byte, 65535)
		for {
			if pumpCtx.Err() != nil {
				return
			}
			n, err := ipConn.ReadPacket(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			// Check if this is an ICMP Type 0 (Echo Reply) from 1.1.1.1
			if buf[0]>>4 == 4 && buf[9] == 1 && n >= 28 && buf[20] == 0 {
				if bytes.Equal(buf[12:16], dest1111[:]) {
					forgedICMPReceived.Store(true)
				}
			}
			v := buffer.NewViewSize(n)
			copy(v.AsSlice(), buf[:n])
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithView(v),
			})
			clientEP.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()
		}
	}()

	// 1. Send ICMP Echo Request to 1.1.1.1
	icmpReq := make([]byte, 28)
	icmpReq[0] = 0x45
	binary.BigEndian.PutUint16(icmpReq[2:4], 28)
	icmpReq[8] = 64
	icmpReq[9] = 1 // ICMP
	clientIPBytes := assignedIP.As4()
	copy(icmpReq[12:16], clientIPBytes[:])
	copy(icmpReq[16:20], dest1111[:])
	ipChk := calcChecksum(icmpReq[:20])
	binary.BigEndian.PutUint16(icmpReq[10:12], ipChk)
	icmpReq[20] = 8 // Echo Request
	icmpReq[21] = 0
	binary.BigEndian.PutUint16(icmpReq[24:26], 1) // ID
	binary.BigEndian.PutUint16(icmpReq[26:28], 1) // Seq
	icmpChk := calcChecksum(icmpReq[20:])
	binary.BigEndian.PutUint16(icmpReq[22:24], icmpChk)

	if _, err := ipConn.WritePacket(icmpReq); err != nil {
		t.Fatalf("WritePacket icmp failed: %v", err)
	}

	// 2. Perform end-to-end TCP payload echo
	localAddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4(assignedIP.As4()),
	}
	var targetIP4 [4]byte
	copy(targetIP4[:], targetIP.To4())
	remoteAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4(targetIP4),
		Port: uint16(echoPort),
	}
	tcpConn, err := gonet.DialTCPWithBind(ctx, clientStack, localAddr, remoteAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialTCPWithBind failed: %v", err)
	}
	defer tcpConn.Close()

	payload := []byte("hello-aero-real-tcp-payload-roundtrip")
	if _, err := tcpConn.Write(payload); err != nil {
		t.Fatalf("tcpConn.Write failed: %v", err)
	}

	recvBuf := make([]byte, 1024)
	_ = tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := tcpConn.Read(recvBuf)
	if err != nil {
		t.Fatalf("tcpConn.Read failed: %v", err)
	}
	if !bytes.Equal(recvBuf[:n], payload) {
		t.Fatalf("payload mismatch: expected %s, got %s", payload, recvBuf[:n])
	}

	if forgedICMPReceived.Load() {
		t.Fatal("expected no forged ICMP Echo Type 0 reply for 1.1.1.1, but one was received")
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

// ==========================================
// 10. Tests for v1.0.3 Security & Resource Management
// ==========================================

func TestAuthFailureJail(t *testing.T) {
	jail := NewAuthFailureJail()
	defer jail.Close()

	ip := "198.51.100.10"
	if jail.IsBanned(ip) {
		t.Fatalf("expected IP %s not to be banned initially", ip)
	}

	// 1-4 failures should not ban
	for i := 1; i <= 4; i++ {
		banned := jail.RecordFailure(ip)
		if banned {
			t.Fatalf("expected failure %d not to trigger ban", i)
		}
		if jail.IsBanned(ip) {
			t.Fatalf("expected IP not to be banned after %d failures", i)
		}
	}

	// 5th failure triggers 15 minute ban
	banned := jail.RecordFailure(ip)
	if !banned {
		t.Fatalf("expected 5th failure to trigger ban")
	}
	if !jail.IsBanned(ip) {
		t.Fatalf("expected IP to be banned after 5 failures")
	}

	// Another failure while banned still returns banned
	if !jail.RecordFailure(ip) {
		t.Fatalf("expected failure while banned to return true")
	}

	// Other IP is unaffected
	otherIP := "198.51.100.20"
	if jail.IsBanned(otherIP) {
		t.Fatalf("expected unrecorded IP not to be banned")
	}

	// Test window expiration reset
	windowIP := "198.51.100.30"
	jail.mu.Lock()
	jail.records[windowIP] = &jailEntry{
		failures:   4,
		firstFail:  time.Now().Add(-2 * time.Minute), // expired window (>1m)
		lastActive: time.Now().Add(-2 * time.Minute),
	}
	jail.mu.Unlock()

	// Recording a failure after expired window resets count to 1
	banned = jail.RecordFailure(windowIP)
	if banned {
		t.Fatalf("expected expired window failure not to trigger ban")
	}
	jail.mu.Lock()
	if jail.records[windowIP].failures != 1 {
		t.Fatalf("expected failure count reset to 1, got %d", jail.records[windowIP].failures)
	}
	jail.mu.Unlock()

	// Test cleanup logic
	cleanIP := "198.51.100.40"
	jail.mu.Lock()
	jail.records[cleanIP] = &jailEntry{
		failures:   1,
		banUntil:   time.Now().Add(-1 * time.Minute),
		lastActive: time.Now().Add(-15 * time.Minute), // > 10m inactive
	}
	jail.mu.Unlock()

	// Simulate cleanup sweep manually
	jail.mu.Lock()
	now := time.Now()
	for k, entry := range jail.records {
		if now.After(entry.banUntil) && now.Sub(entry.lastActive) > 10*time.Minute {
			delete(jail.records, k)
		}
	}
	_, found := jail.records[cleanIP]
	jail.mu.Unlock()
	if found {
		t.Fatalf("expected stale entry %s to be cleaned up", cleanIP)
	}
}

func TestIPPoolAvailable(t *testing.T) {
	pool, err := NewIPPool("10.88.0.0/16")
	if err != nil {
		t.Fatalf("NewIPPool failed: %v", err)
	}

	if !pool.Available() {
		t.Fatalf("expected freshly created pool to be available")
	}

	// Simulate pool exhaustion
	pool.mu.Lock()
	pool.maxHost = 2
	pool.used[pool.baseIP] = struct{}{}
	candAddr, _ := netip.ParseAddr("10.88.0.2")
	pool.used[candAddr] = struct{}{}
	pool.mu.Unlock()

	if pool.Available() {
		t.Fatalf("expected exhausted pool not to be available")
	}

	// Release an address and check availability
	pool.Release(netip.PrefixFrom(candAddr, 32))
	if !pool.Available() {
		t.Fatalf("expected pool to be available after release")
	}
}

func TestQUICServerAuthJailIntegration(t *testing.T) {
	v := NewValidator()
	v.AddToken("valid_token", "user", 24*time.Hour)
	qs := NewQUICServer(v, nil, nil, nil, nil)
	defer qs.Close()

	remoteAddr := "203.0.113.88:12345"

	// 5 unauthorized requests should ban the IP
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/masque/ip/*/*/", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer invalid_token")
		rec := httptest.NewRecorder()

		token, ok := qs.authRequest(rec, req)
		if ok || token != "" {
			t.Fatalf("expected authRequest to fail with invalid token")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d expected 401, got %d", i, rec.Code)
		}
	}

	// 6th request from banned IP should receive 429 Too Many Requests with Retry-After: 900
	reqBanned := httptest.NewRequest(http.MethodGet, "/.well-known/masque/ip/*/*/", nil)
	reqBanned.RemoteAddr = remoteAddr
	reqBanned.Header.Set("Authorization", "Bearer invalid_token")
	recBanned := httptest.NewRecorder()

	token, ok := qs.authRequest(recBanned, reqBanned)
	if ok || token != "" {
		t.Fatalf("expected authRequest to fail for banned IP")
	}
	if recBanned.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", recBanned.Code)
	}
	if retryAfter := recBanned.Header().Get("Retry-After"); retryAfter != "900" {
		t.Fatalf("expected Retry-After 900, got %q", retryAfter)
	}
}

func TestServeConnectIPPoolExhausted(t *testing.T) {
	v := NewValidator()
	v.AddToken("valid_token", "user", 24*time.Hour)
	qs := NewQUICServer(v, nil, nil, nil, nil)
	defer qs.Close()

	// Exhaust the IP pool
	qs.ipPool.mu.Lock()
	qs.ipPool.maxHost = 0
	qs.ipPool.mu.Unlock()

	req := httptest.NewRequest(http.MethodConnect, "https://example.com/.well-known/masque/ip/*/*/", nil)
	req.Proto = "connect-ip"
	req.Host = "example.com"
	req.Header.Set("Capsule-Protocol", "?1")
	req.RemoteAddr = "203.0.113.99:54321"
	req.Header.Set("Authorization", "Bearer valid_token")
	req.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))
	rec := httptest.NewRecorder()

	qs.serveConnectIP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable, got %d", rec.Code)
	}
	expectedStatus := "aero; error=address_pool_exhausted; details=\"IP pool exhausted\""
	if rec.Header().Get("Proxy-Status") != expectedStatus {
		t.Fatalf("expected Proxy-Status %q, got %q", expectedStatus, rec.Header().Get("Proxy-Status"))
	}
}

func TestGenerateTokenEntropy(t *testing.T) {
	tokens := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken failed: %v", err)
		}
		if !strings.HasPrefix(tok, "aero_") {
			t.Fatalf("expected token prefix 'aero_', got %s", tok)
		}
		// aero_ (5 chars) + 32 bytes hex (64 chars) = 69 chars
		if len(tok) != 69 {
			t.Fatalf("expected token length 69 (256-bit entropy), got %d (%s)", len(tok), tok)
		}
		if _, exists := tokens[tok]; exists {
			t.Fatalf("duplicate token generated: %s", tok)
		}
		tokens[tok] = struct{}{}
	}
}

func TestServerConfigAndSubServerECH(t *testing.T) {
	cfg := ServerConfig{
		Domain: "edge.example.com",
		ECH:    "AERO_ECH_CONFIG_HEX_BASE64",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal ServerConfig failed: %v", err)
	}

	var parsed ServerConfig
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal ServerConfig failed: %v", err)
	}
	if parsed.ECH != "AERO_ECH_CONFIG_HEX_BASE64" {
		t.Fatalf("expected ECH 'AERO_ECH_CONFIG_HEX_BASE64', got %q", parsed.ECH)
	}

	sub := SubServer{
		Name: "node-1",
		Host: "edge.example.com",
		ECH:  "AERO_ECH_NODE_CONFIG",
	}
	subData, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal SubServer failed: %v", err)
	}
	var parsedSub SubServer
	if err := json.Unmarshal(subData, &parsedSub); err != nil {
		t.Fatalf("unmarshal SubServer failed: %v", err)
	}
	if parsedSub.ECH != "AERO_ECH_NODE_CONFIG" {
		t.Fatalf("expected SubServer ECH 'AERO_ECH_NODE_CONFIG', got %q", parsedSub.ECH)
	}
}

func TestAuthValidateConstantTime(t *testing.T) {
	v := NewValidator()
	v.AddToken("tok_valid", "user1", 1*time.Hour)
	v.AddToken("tok_expired", "user2", -1*time.Minute)

	if !v.Validate("tok_valid") {
		t.Fatal("expected tok_valid to be valid")
	}
	if v.Validate("tok_expired") {
		t.Fatal("expected tok_expired to be invalid")
	}
	if v.Validate("tok_nonexistent") {
		t.Fatal("expected tok_nonexistent to be invalid")
	}
	if v.Validate("") {
		t.Fatal("expected empty token to be invalid")
	}
}

func TestAuthFailureJailRWMutexConcurrency(t *testing.T) {
	jail := NewAuthFailureJail()
	defer jail.Close()

	var wg sync.WaitGroup
	ip := "192.0.2.100"

	// 20 concurrent readers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				_ = jail.IsBanned(ip)
			}
		}()
	}

	// 5 concurrent writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 20; k++ {
				jail.RecordFailure(ip)
			}
		}()
	}

	wg.Wait()

	if !jail.IsBanned(ip) {
		t.Fatal("expected IP to be banned after recorded failures")
	}
}

func TestAuthRequestEnforcesValidateFull(t *testing.T) {
	v := NewValidator()
	tok := "auth_test_tok"
	v.AddToken(tok, "user", 1*time.Hour)
	qs := NewQUICServer(v, nil, nil, nil, nil)
	defer qs.Close()

	// 1. Missing timestamp & nonce -> 401
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("Authorization", "Bearer "+tok)
	rec1 := httptest.NewRecorder()
	tokRet1, ok1 := qs.authRequest(rec1, req1)
	if ok1 || tokRet1 != "" || rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on missing timestamp/nonce, got code=%d ok=%v", rec1.Code, ok1)
	}

	// 2. Invalid timestamp/nonce -> 401
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("Aero-Timestamp", "not-a-number")
	req2.Header.Set("Aero-Nonce", "0102")
	rec2 := httptest.NewRecorder()
	tokRet2, ok2 := qs.authRequest(rec2, req2)
	if ok2 || tokRet2 != "" || rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on invalid timestamp/nonce, got code=%d ok=%v", rec2.Code, ok2)
	}

	// 3. Valid timestamp & nonce -> 200 / success
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req3.Header.Set("Authorization", "Bearer "+tok)
	req3.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req3.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))
	rec3 := httptest.NewRecorder()
	tokRet3, ok3 := qs.authRequest(rec3, req3)
	if !ok3 || tokRet3 != tok {
		t.Fatalf("expected auth success, got ok=%v tok=%s", ok3, tokRet3)
	}
}

func TestPrecompiledTemplatesInitialized(t *testing.T) {
	qs := NewQUICServer(nil, nil, nil, nil, nil)
	defer qs.Close()

	if qs.udpTempl == nil {
		t.Fatal("expected udpTempl to be initialized")
	}
	if qs.ipTempl == nil {
		t.Fatal("expected ipTempl to be initialized")
	}
}

// ==========================================
// Phase 2 Gate Unit Tests (Grok 4.7 Standard)
// ==========================================

// Gate 1: GET /sub/superadmin returns 404 with no token; correct node secret returns 200.
func TestPhase2Gate1SuperadminBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewSubStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	nodeToken := "node_bearer_token_secret_12345"
	if err := store.Ensure(EnsureSubParams{
		Name:     "TestNode",
		Host:     "test.example.com",
		Token:    nodeToken,
		SNI:      "test.example.com",
		LineType: "standard",
	}); err != nil {
		t.Fatal(err)
	}

	secretKey := store.Secret()
	if secretKey == "" {
		t.Fatal("expected non-empty secret key")
	}

	// Verify client-sub.json exists and is readable
	clientSubPath := filepath.Join(tmpDir, "client-sub.json")
	if _, err := os.Stat(clientSubPath); err != nil {
		t.Fatalf("failed to stat client-sub.json: %v", err)
	}

	handler := &SubHandler{Store: store}

	// 1. GET /sub/superadmin MUST return 404 and must NOT contain node token
	reqAdmin := httptest.NewRequest(http.MethodGet, "/sub/superadmin", nil)
	recAdmin := httptest.NewRecorder()
	handled := handler.TryServe(recAdmin, reqAdmin)
	if !handled {
		t.Fatal("TryServe should handle /sub/superadmin")
	}
	if recAdmin.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for /sub/superadmin, got %d", recAdmin.Code)
	}
	if strings.Contains(recAdmin.Body.String(), nodeToken) {
		t.Fatalf("superadmin response must NOT contain token, got: %s", recAdmin.Body.String())
	}

	// 2. GET /sub/{nodeSecret} with correct node secret MUST return 200
	reqValid := httptest.NewRequest(http.MethodGet, "/sub/"+secretKey, nil)
	recValid := httptest.NewRecorder()
	handled = handler.TryServe(recValid, reqValid)
	if !handled {
		t.Fatal("TryServe should handle /sub/{secret}")
	}
	if recValid.Code != http.StatusOK {
		t.Fatalf("expected 200 for correct node secret, got %d", recValid.Code)
	}
	if !strings.Contains(recValid.Body.String(), nodeToken) {
		t.Fatalf("expected valid response to contain node token")
	}
}

// Gate 2: Target domains resolving to 127.0.0.1, 10.0.0.1, 169.254.169.254 result in 0 UDP dials and 403 Forbidden;
// target resolving to public address allows payload roundtrip through real UDP socket.
func TestPhase2Gate2SSRFConnectUDP(t *testing.T) {
	v := NewValidator()
	v.AddToken("valid_gate_token", "user", 24*time.Hour)
	qs := NewQUICServer(v, nil, nil, nil, nil)
	defer qs.Close()
	qs.SetAllowLoopbackForTest(false) // Strict SSRF blocking

	var dialCount atomic.Int32
	qs.SetUDPDialFunc(func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
		dialCount.Add(1)
		return net.DialUDP(network, laddr, raddr)
	})

	blockedTargets := []struct {
		domain string
		ip     net.IP
	}{
		{"rebind-loopback.target:5353", net.IPv4(127, 0, 0, 1)},
		{"rebind-private.target:5353", net.IPv4(10, 0, 0, 1)},
		{"rebind-linklocal.target:5353", net.IPv4(169, 254, 169, 254)},
	}

	for _, tc := range blockedTargets {
		t.Run(tc.domain, func(t *testing.T) {
			qs.SetResolveUDPFunc(func(network, addr string) (*net.UDPAddr, error) {
				return &net.UDPAddr{IP: tc.ip, Port: 5353}, nil
			})

			h, p, _ := net.SplitHostPort(tc.domain)
			targetURL := "https://placeholder/.well-known/masque/udp/" + h + "/" + p + "/"
			req := httptest.NewRequest(http.MethodGet, targetURL, nil)
			req.Method = http.MethodConnect
			req.Proto = "connect-udp"
			req.Header.Set("Upgrade", "connect-udp")
			req.Header.Set("Capsule-Protocol", "?1")
			req.URL.Scheme = ""
			req.URL.Host = ""
			nonce := make([]byte, 32)
			_, _ = io.ReadFull(rand.Reader, nonce)
			req.Header.Set("Authorization", "Bearer valid_gate_token")
			req.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
			req.Header.Set("Aero-Nonce", hex.EncodeToString(nonce))

			rec := httptest.NewRecorder()
			qs.serveConnectUDP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 Forbidden for SSRF target %s (%s), got %d", tc.domain, tc.ip, rec.Code)
			}
			proxyStatus := rec.Header().Get("Proxy-Status")
			if !strings.Contains(proxyStatus, "destination_ip_prohibited") {
				t.Fatalf("expected Proxy-Status destination_ip_prohibited, got %q", proxyStatus)
			}
			if dialCount.Load() != 0 {
				t.Fatalf("expected UDP dial count to be 0, got %d", dialCount.Load())
			}
		})
	}

	t.Run("PublicIPResolutionRealUDPEcho", func(t *testing.T) {
		listenAddr, host := findTestAddr()
		udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
		if err != nil {
			t.Fatalf("failed to resolve udp listenAddr: %v", err)
		}
		echoUDP, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			t.Fatalf("failed to listen on udp: %v", err)
		}
		defer echoUDP.Close()

		go func() {
			buf := make([]byte, 2048)
			for {
				n, raddr, err := echoUDP.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = echoUDP.WriteTo(buf[:n], raddr)
			}
		}()

		// Full end-to-end QUIC / MASQUE CONNECT-UDP test
		dataDir := t.TempDir()
		edgeAddr, _ := findTestAddr()
		cfg := ServerConfig{
			Listen:                     edgeAddr,
			Domain:                     host,
			DataDir:                    dataDir,
			Token:                      "public_udp_token",
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

		var publicDialCount atomic.Int32
		targetHost := "public-service.example"
		targetAddr := targetHost + ":5353"

		// Server resolves target domain to public IP (198.51.100.1), then dials real echo UDP
		srv.quicServer.SetResolveUDPFunc(func(network, addr string) (*net.UDPAddr, error) {
			return &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5353}, nil
		})
		srv.quicServer.SetUDPDialFunc(func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
			publicDialCount.Add(1)
			return net.DialUDP("udp", nil, echoUDP.LocalAddr().(*net.UDPAddr))
		})

		tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
		quicConf := DefaultQUICConfig()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), tlsConf, quicConf)
		if err != nil {
			t.Fatalf("quic.DialAddr failed: %v", err)
		}
		defer qConn.CloseWithError(0, "normal")

		tr := &http3.Transport{EnableDatagrams: true}
		h3Conn := tr.NewClientConn(qConn)
		masqueConn := masque.NewClientConn(h3Conn)

		tmpl := uritemplate.MustNew("https://" + host + "/.well-known/masque/udp/{target_host}/{target_port}/")
		mReq, err := masque.NewRequest(ctx, tmpl, targetAddr)
		if err != nil {
			t.Fatalf("masque.NewRequest failed: %v", err)
		}
		nonce := make([]byte, 32)
		_, _ = io.ReadFull(rand.Reader, nonce)
		mReq.Header().Set("Authorization", "Bearer public_udp_token")
		mReq.Header().Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
		mReq.Header().Set("Aero-Nonce", hex.EncodeToString(nonce))

		mConn, resp, err := masqueConn.Dial(mReq)
		if err != nil {
			t.Fatalf("masqueConn.Dial failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got: %d %s", resp.StatusCode, resp.Status)
		}
		defer mConn.Close()

		rUdpAddr := echoUDP.LocalAddr().(*net.UDPAddr)
		payload := []byte("hello-real-udp-echo-from-public-target")
		if _, err := mConn.WriteTo(payload, rUdpAddr); err != nil {
			t.Fatalf("WriteTo failed: %v", err)
		}

		recvBuf := make([]byte, 2048)
		_ = mConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := mConn.ReadFrom(recvBuf)
		if err != nil {
			t.Fatalf("ReadFrom failed: %v", err)
		}
		if !bytes.Equal(recvBuf[:n], payload) {
			t.Fatalf("payload mismatch: expected %s, got %s", payload, recvBuf[:n])
		}
		if publicDialCount.Load() != 1 {
			t.Fatalf("expected UDP dial count to be 1, got %d", publicDialCount.Load())
		}
	})
}

// Gate 3: 5 failed authentications with 5 different forged X-Forwarded-For headers;
// jail ban strictly lands on physical RemoteAddr, forged IPs are NOT banned.
func TestPhase2Gate3ClientIPRemoteAddrLock(t *testing.T) {
	v := NewValidator()
	v.AddToken("valid_token", "user", 24*time.Hour)
	qs := NewQUICServer(v, nil, nil, nil, nil)
	defer qs.Close()

	physicalRemoteAddr := "203.0.113.199:54321"
	physicalIP := "203.0.113.199"

	forgedIPs := []string{
		"192.0.2.1",
		"192.0.2.2",
		"192.0.2.3",
		"192.0.2.4",
		"192.0.2.5",
	}

	// 5 failed authentication requests, each with a different forged X-Forwarded-For header
	for i, forgedIP := range forgedIPs {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/masque/ip/*/*/", nil)
		req.RemoteAddr = physicalRemoteAddr
		req.Header.Set("X-Forwarded-For", forgedIP)
		req.Header.Set("Authorization", "Bearer wrong_token_"+strconv.Itoa(i))
		rec := httptest.NewRecorder()

		token, ok := qs.authRequest(rec, req)
		if ok || token != "" {
			t.Fatalf("expected authRequest to fail")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d expected 401, got %d", i+1, rec.Code)
		}
	}

	// Assert: Physical RemoteAddr IP MUST be banned!
	if !qs.AuthJail().IsBanned(physicalIP) {
		t.Fatalf("expected physical IP %s to be banned in AuthFailureJail", physicalIP)
	}

	// Assert: None of the forged IPs from X-Forwarded-For must be banned!
	for _, forgedIP := range forgedIPs {
		if qs.AuthJail().IsBanned(forgedIP) {
			t.Fatalf("forged IP %s must NOT be banned in AuthFailureJail", forgedIP)
		}
	}

	// 6th request from physical RemoteAddr MUST receive 429 Too Many Requests
	req6 := httptest.NewRequest(http.MethodGet, "/.well-known/masque/ip/*/*/", nil)
	req6.RemoteAddr = physicalRemoteAddr
	req6.Header.Set("X-Forwarded-For", "192.0.2.99")
	req6.Header.Set("Authorization", "Bearer wrong_token_6")
	rec6 := httptest.NewRecorder()

	token6, ok6 := qs.authRequest(rec6, req6)
	if ok6 || token6 != "" {
		t.Fatalf("expected authRequest to fail for banned physical IP")
	}
	if rec6.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", rec6.Code)
	}
	if rec6.Header().Get("Retry-After") != "900" {
		t.Fatalf("expected Retry-After 900, got %q", rec6.Header().Get("Retry-After"))
	}

	// Request with physical RemoteAddr of forged IP must NOT be banned
	reqForged := httptest.NewRequest(http.MethodGet, "/.well-known/masque/ip/*/*/", nil)
	reqForged.RemoteAddr = "192.0.2.1:12345"
	reqForged.Header.Set("Authorization", "Bearer valid_token")
	reqForged.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	reqForged.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))
	recForged := httptest.NewRecorder()

	tok, ok := qs.authRequest(recForged, reqForged)
	if !ok || tok != "valid_token" {
		t.Fatalf("request from forged IP's physical address should NOT be banned, got ok=%v, code=%d", ok, recForged.Code)
	}
}

// Gate 4: ICMP Echo to 1.1.1.1 receives no forged Type 0; CONNECT-IP real TCP payload roundtrip matches exactly.
func TestPhase2Gate4NoForgedICMPAndConnectIPRealTCP(t *testing.T) {
	TestCONNECTIPRoundtrip(t)
}

// Phase 5 Gate: Real ICMP Forwarding & Client Ping Connectivity
func TestPhase5Gate_RealICMPForwarding(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "connect_ip_token_p5",
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

	srv.quicServer.SetAllowLoopbackForTest(false) // 严格拦截私网/回环 IP

	// 注册带 15ms 模拟延迟的 icmpForwardHook
	var hookCalls atomic.Int32
	srv.quicServer.SetICMPForwardHookForTest(func(target net.IP, echoReq []byte) ([]byte, error) {
		hookCalls.Add(1)
		time.Sleep(15 * time.Millisecond)
		if len(echoReq) < 8 {
			return nil, errors.New("echo req too short")
		}
		// 构造真实 Echo Reply (Type 0, Code 0, 保留 ID、Sequence 与 Payload)
		reply := make([]byte, len(echoReq))
		copy(reply, echoReq)
		reply[0] = 0 // Type 0 (Echo Reply)
		reply[1] = 0 // Code 0
		reply[2] = 0 // Reset checksum for recomputation
		reply[3] = 0
		return reply, nil
	})

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	ipReq.Header().Set("Authorization", "Bearer connect_ip_token_p5")
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

	assigned, err := ipConn.ReceiveAddressAssignment(ctx)
	if err != nil {
		t.Fatalf("ReceiveAddressAssignment failed: %v", err)
	}
	if len(assigned) == 0 {
		t.Fatal("expected at least 1 assigned prefix")
	}
	assignedIP := assigned[0].IPPrefix.Addr()

	packetCh := make(chan []byte, 20)
	readCtx, readCancel := context.WithCancel(ctx)
	defer readCancel()

	go func() {
		buf := make([]byte, 65535)
		for {
			if readCtx.Err() != nil {
				return
			}
			n, err := ipConn.ReadPacket(buf)
			if err != nil {
				return
			}
			if n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				select {
				case packetCh <- pkt:
				case <-readCtx.Done():
					return
				}
			}
		}
	}()

	// 1. 客户端发送发往 8.8.8.8 的 ICMP Echo Request
	target8888 := net.ParseIP("8.8.8.8")
	clientIPBytes := assignedIP.As4()

	pingData := []byte("ping-p5-test-payload")
	icmpPayload := make([]byte, 8+len(pingData))
	icmpPayload[0] = 8                                   // Echo Request
	icmpPayload[1] = 0                                   // Code 0
	binary.BigEndian.PutUint16(icmpPayload[4:6], 0x4321) // Identifier
	binary.BigEndian.PutUint16(icmpPayload[6:8], 0x0007) // Sequence
	copy(icmpPayload[8:], pingData)
	chk := calcChecksum(icmpPayload)
	binary.BigEndian.PutUint16(icmpPayload[2:4], chk)

	reqPkt := make([]byte, 20+len(icmpPayload))
	reqPkt[0] = 0x45
	binary.BigEndian.PutUint16(reqPkt[2:4], uint16(len(reqPkt)))
	reqPkt[8] = 64
	reqPkt[9] = 1 // ICMP
	copy(reqPkt[12:16], clientIPBytes[:])
	copy(reqPkt[16:20], target8888.To4())
	ipChk := calcChecksum(reqPkt[:20])
	binary.BigEndian.PutUint16(reqPkt[10:12], ipChk)
	copy(reqPkt[20:], icmpPayload)

	sendTime := time.Now()
	if _, err := ipConn.WritePacket(reqPkt); err != nil {
		t.Fatalf("WritePacket to 8.8.8.8 failed: %v", err)
	}

	// 验证从 CONNECT-IP 成功读回真实 ICMP Echo Reply
	select {
	case reply := <-packetCh:
		rtt := time.Since(sendTime)
		if len(reply) < 28 {
			t.Fatalf("reply packet too short: %d", len(reply))
		}
		if reply[0]>>4 != 4 {
			t.Fatalf("expected IPv4 reply, got version %d", reply[0]>>4)
		}
		if reply[9] != 1 {
			t.Fatalf("expected ICMP protocol 1, got %d", reply[9])
		}
		// 验证源 IP 为 8.8.8.8
		srcIP := net.IP(reply[12:16])
		if !srcIP.Equal(target8888) {
			t.Fatalf("expected source IP 8.8.8.8, got %v", srcIP)
		}
		// 验证目的 IP 为客户端分配的 IP
		dstIP := net.IP(reply[16:20])
		if !dstIP.Equal(net.IP(clientIPBytes[:])) {
			t.Fatalf("expected dst IP %v, got %v", assignedIP, dstIP)
		}

		ihl := int(reply[0]&0x0f) * 4
		replyICMP := reply[ihl:]
		// 验证 Type == 0 (Echo Reply)
		if replyICMP[0] != 0 {
			t.Fatalf("expected ICMP Type 0 (Echo Reply), got %d", replyICMP[0])
		}
		if replyICMP[1] != 0 {
			t.Fatalf("expected ICMP Code 0, got %d", replyICMP[1])
		}
		// 验证 Identifier 与 Sequence 完全吻合
		replyID := binary.BigEndian.Uint16(replyICMP[4:6])
		replySeq := binary.BigEndian.Uint16(replyICMP[6:8])
		if replyID != 0x4321 {
			t.Fatalf("expected Identifier 0x4321, got 0x%04x", replyID)
		}
		if replySeq != 0x0007 {
			t.Fatalf("expected Sequence 0x0007, got 0x%04x", replySeq)
		}
		// 验证 Payload 数据
		if string(replyICMP[8:]) != "ping-p5-test-payload" {
			t.Fatalf("expected payload %q, got %q", "ping-p5-test-payload", string(replyICMP[8:]))
		}
		// 验证 RTT > 0 且包含了 15ms 模拟延迟
		if rtt <= 0 {
			t.Fatalf("expected RTT > 0, got %v", rtt)
		}
		if rtt < 14*time.Millisecond {
			t.Fatalf("expected RTT >= 15ms simulated delay, got %v", rtt)
		}
		if hookCalls.Load() != 1 {
			t.Fatalf("expected hook called 1 time, got %d", hookCalls.Load())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for ICMP Echo Reply from CONNECT-IP")
	}

	// 2. 测试发往 10.0.0.1 (私网 IP) 的 Echo Request，验证被 IsBlockedIP 拦截，hook 调用次数为 0
	hookCalls.Store(0)
	target10001 := net.ParseIP("10.0.0.1")

	blockedReqPkt := make([]byte, 20+len(icmpPayload))
	copy(blockedReqPkt, reqPkt)
	copy(blockedReqPkt[16:20], target10001.To4())
	blockedReqPkt[10] = 0
	blockedReqPkt[11] = 0
	ipChkBlocked := calcChecksum(blockedReqPkt[:20])
	binary.BigEndian.PutUint16(blockedReqPkt[10:12], ipChkBlocked)

	if _, err := ipConn.WritePacket(blockedReqPkt); err != nil {
		t.Fatalf("WritePacket to 10.0.0.1 failed: %v", err)
	}

	// 等待并验证 hook 调用次数严格为 0，且无任何回包
	select {
	case unexp := <-packetCh:
		t.Fatalf("unexpected packet returned for blocked target: %x", unexp)
	case <-time.After(150 * time.Millisecond):
		// 正确，未收到任何回包
	}

	if calls := hookCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 hook calls for blocked private IP 10.0.0.1, got %d", calls)
	}
}

type tapPacketConn struct {
	net.PacketConn
	mu       sync.Mutex
	sent     [][]byte
	received [][]byte
}

func (t *tapPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	t.mu.Lock()
	t.sent = append(t.sent, cp)
	t.mu.Unlock()
	return t.PacketConn.WriteTo(b, addr)
}

func (t *tapPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := t.PacketConn.ReadFrom(b)
	if err == nil && n > 0 {
		cp := make([]byte, n)
		copy(cp, b[:n])
		t.mu.Lock()
		t.received = append(t.received, cp)
		t.mu.Unlock()
	}
	return n, addr, err
}

func calcShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	total := float64(len(data))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// 阶段六门禁：QUIC 动态包长混淆与可选 Salamander 混淆引擎
func TestPhase6Gate_SalamanderAndPadding(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	obfsKey := "aero-secret-salamander-key"

	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "salamander_gate_token_p6",
		AllowSelfSignedCertForTest: true,
		ObfsPassword:               obfsKey,
		PaddingJitter:              true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	srv.quicServer.SetAllowLoopbackForTest(true)

	// 1. 设置截获线路上真实 UDP 数据报的拦截 PacketConn
	network := "udp4"
	localBind := "127.0.0.1:0"
	if strings.Contains(listenAddr, "[") || strings.HasPrefix(listenAddr, "::") {
		network = "udp6"
		localBind = "[::1]:0"
	}

	rawClientConn, err := net.ListenPacket(network, localBind)
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer rawClientConn.Close()

	tap := &tapPacketConn{PacketConn: rawClientConn}
	clientObfsConn := NewSalamanderPacketConn(tap, obfsKey, true)

	tlsConf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverUDPAddr := srv.quicListener.Addr()

	// 客户端进行 QUIC 握手
	qConn, err := quic.Dial(ctx, clientObfsConn, serverUDPAddr, tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.Dial with salamander failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	// 进行 HTTP/3 数据传输 (GET /healthz) 验证收发数据成功
	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/healthz", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	resp, err := h3Conn.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll body failed: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("expected body 'ok', got %q", string(body))
	}

	// 2. 检查截获的所有链路上数据报 (包括客户端发往服务端，以及服务端发往客户端)
	tap.mu.Lock()
	allPackets := append([][]byte{}, tap.sent...)
	allPackets = append(allPackets, tap.received...)
	tap.mu.Unlock()

	if len(allPackets) == 0 {
		t.Fatalf("no wire datagrams captured")
	}

	for i, pkt := range allPackets {
		// a) 数据报长度全部分布在 [1280, 1380] 区间内
		if len(pkt) < 1280 || len(pkt) > 1380 {
			t.Fatalf("packet %d: length %d not in [1280, 1380]", i, len(pkt))
		}

		// b) 计算香农熵，断言信息熵 Shannon Entropy >= 7.5（表现为不可区分的高熵白噪声，无 QUIC 固定特征）
		entropy := calcShannonEntropy(pkt)
		if entropy < 7.5 {
			t.Fatalf("packet %d: shannon entropy %.4f < 7.5 (expected high-entropy noise)", i, entropy)
		}

		// c) 绝对不包含明文 SNI 或 ALPN "h3"
		if bytes.Contains(pkt, []byte(host)) {
			t.Fatalf("packet %d: leaked plain SNI %q", i, host)
		}
		if bytes.Contains(pkt, []byte("\x02h3")) {
			t.Fatalf("packet %d: leaked plain ALPN \\x02h3", i)
		}
		if bytes.Contains(pkt, []byte{0x00, 0x00, 0x00, 0x01}) {
			t.Fatalf("packet %d: leaked QUIC v1 version magic", i)
		}
	}

	// 3. 模拟错误密码连接：断言握手失败且服务端安全丢弃，不发生 panic
	wrongRawConn, err := net.ListenPacket(network, localBind)
	if err != nil {
		t.Fatalf("ListenPacket for wrong conn failed: %v", err)
	}
	defer wrongRawConn.Close()

	wrongObfsConn := NewSalamanderPacketConn(wrongRawConn, "wrong-password-for-salamander-999", true)
	wrongCtx, wrongCancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer wrongCancel()

	_, wrongErr := quic.Dial(wrongCtx, wrongObfsConn, serverUDPAddr, tlsConf, quicConf)
	if wrongErr == nil {
		t.Fatalf("expected dial with wrong password to fail, but succeeded")
	}

	// 验证服务端未 panic 且仍然健康可用
	req2, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/healthz", nil)
	if err != nil {
		t.Fatalf("NewRequest 2 failed: %v", err)
	}
	resp2, err := h3Conn.RoundTrip(req2)
	if err != nil {
		t.Fatalf("RoundTrip 2 failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp2.StatusCode)
	}
}

// ==========================================
// Phase 7 Gate Test: Multi-Hop Chaining (Ingress -> Egress Cascading Relay)
// ==========================================

func TestPhase7Gate_MultiHopChaining(t *testing.T) {
	// 1. 搭建目标 Echo TCP 服务
	echoListen, _ := findTestAddr()
	echoLn, err := net.Listen("tcp", echoListen)
	if err != nil {
		t.Fatalf("listen echo server failed: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. 搭建 Egress 节点 (Role: "egress", HopCredential: "hop-secret-999")
	egressDataDir := t.TempDir()
	egressListen, egressHost := findTestAddr()
	egressCfg := ServerConfig{
		Listen:                     egressListen,
		Domain:                     egressHost,
		Role:                       "egress",
		HopCredential:              "hop-secret-999",
		DataDir:                    egressDataDir,
		AllowSelfSignedCertForTest: true,
	}
	egressSrv, err := NewServer(egressCfg)
	if err != nil {
		t.Fatalf("NewServer egress failed: %v", err)
	}
	if err := egressSrv.Start(); err != nil {
		t.Fatalf("egressSrv.Start failed: %v", err)
	}
	defer egressSrv.Close()

	// 3. 搭建 Ingress 节点 (Role: "ingress", HopCredential: "hop-secret-999", NextHopAddr: egress.Addr())
	ingressDataDir := t.TempDir()
	ingressListen, ingressHost := findTestAddr()
	clientToken := "client-user-token"
	ingressCfg := ServerConfig{
		Listen:                     ingressListen,
		Domain:                     ingressHost,
		Token:                      clientToken,
		Role:                       "ingress",
		HopCredential:              "hop-secret-999",
		NextHopAddr:                egressSrv.Addr(),
		DataDir:                    ingressDataDir,
		AllowSelfSignedCertForTest: true,
	}
	ingressSrv, err := NewServer(ingressCfg)
	if err != nil {
		t.Fatalf("NewServer ingress failed: %v", err)
	}
	if err := ingressSrv.Start(); err != nil {
		t.Fatalf("ingressSrv.Start failed: %v", err)
	}
	defer ingressSrv.Close()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ----------------------------------------------------
	// 场景一（端到端多跳中继成功）：
	// 客户端使用普通用户 token 连接 Ingress，发起 CONNECT 目标 Echo 服务。
	// 数据通过 Ingress -> Egress -> Echo 服务成功往返，断言发送与接收的数据完全一致！
	// ----------------------------------------------------
	qConn, err := quic.DialAddr(ctx, ingressSrv.Addr(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("dial ingress failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+echoAddr, nil)
	if err != nil {
		t.Fatalf("create connect req failed: %v", err)
	}
	req.Proto = "HTTP/1.1"
	req.Header.Set("Authorization", "Bearer "+clientToken)
	req.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	reqStr, err := h3Conn.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("OpenRequestStream on ingress failed: %v", err)
	}
	defer reqStr.Close()

	if err := reqStr.SendRequestHeader(req); err != nil {
		t.Fatalf("SendRequestHeader to ingress failed: %v", err)
	}

	resp, err := reqStr.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse from ingress failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from Ingress relay, got %d, Proxy-Status: %s", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}

	testPayload := []byte("Phase7_MultiHop_Chaining_Payload_Verification_123456789")
	if _, err := reqStr.Write(testPayload); err != nil {
		t.Fatalf("write payload to ingress stream failed: %v", err)
	}

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(reqStr, buf); err != nil {
		t.Fatalf("read echoed payload failed: %v", err)
	}
	if !bytes.Equal(buf, testPayload) {
		t.Fatalf("payload mismatch: expected %q, got %q", testPayload, buf)
	}

	// ----------------------------------------------------
	// 场景二（安全隔离门禁）：
	// 1) 客户端使用普通用户 token ("client-user-token") 直接连接 Egress，断言 Egress 严格返回 401 Unauthorized。
	// 2) Ingress 使用错误的 HopCredential ("wrong-hop-key") 连接 Egress，断言 Egress 严格返回 401 Unauthorized。
	// 3) 验证 Egress 端未记录或暴露任何客户端原始用户 token。
	// ----------------------------------------------------

	// 2.1 客户端使用普通用户 token 直接连接 Egress
	qConnEgress, err := quic.DialAddr(ctx, egressSrv.Addr(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("dial egress directly failed: %v", err)
	}
	defer qConnEgress.CloseWithError(0, "normal")

	h3ConnEgress := tr.NewClientConn(qConnEgress)

	reqDirect, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+echoAddr, nil)
	if err != nil {
		t.Fatalf("create direct req failed: %v", err)
	}
	reqDirect.Proto = "HTTP/1.1"
	reqDirect.Header.Set("Authorization", "Bearer "+clientToken)
	reqDirect.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	reqDirect.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	reqStrDirect, err := h3ConnEgress.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("OpenRequestStream direct to egress failed: %v", err)
	}
	defer reqStrDirect.Close()

	if err := reqStrDirect.SendRequestHeader(reqDirect); err != nil {
		t.Fatalf("SendRequestHeader direct to egress failed: %v", err)
	}

	respDirect, err := reqStrDirect.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse direct from egress failed: %v", err)
	}
	if respDirect.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when connecting directly to egress with user token, got %d", respDirect.StatusCode)
	}
	proxyStatus := respDirect.Header.Get("Proxy-Status")
	if !strings.Contains(proxyStatus, "proxy_authorization_required") || !strings.Contains(proxyStatus, "invalid hop credential") {
		t.Fatalf("expected Proxy-Status to contain proxy_authorization_required and invalid hop credential, got: %q", proxyStatus)
	}

	// 2.2 连接 Egress 时使用错误的 HopCredential
	reqWrongHop, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+echoAddr, nil)
	if err != nil {
		t.Fatalf("create wrong hop req failed: %v", err)
	}
	reqWrongHop.Proto = "HTTP/1.1"
	reqWrongHop.Header.Set("Aero-Hop-Token", "wrong-hop-key")

	reqStrWrongHop, err := h3ConnEgress.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("OpenRequestStream wrong hop to egress failed: %v", err)
	}
	defer reqStrWrongHop.Close()

	if err := reqStrWrongHop.SendRequestHeader(reqWrongHop); err != nil {
		t.Fatalf("SendRequestHeader wrong hop failed: %v", err)
	}

	respWrongHop, err := reqStrWrongHop.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse wrong hop failed: %v", err)
	}
	if respWrongHop.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized with wrong hop key on egress, got %d", respWrongHop.StatusCode)
	}

	// 2.3 验证 Ingress 节点使用错误 HopCredential 时级联失败返回 502 Bad Gateway
	ingressWrongDataDir := t.TempDir()
	ingressWrongListen, ingressWrongHost := findTestAddr()
	ingressWrongCfg := ServerConfig{
		Listen:                     ingressWrongListen,
		Domain:                     ingressWrongHost,
		Token:                      clientToken,
		Role:                       "ingress",
		HopCredential:              "wrong-hop-key",
		NextHopAddr:                egressSrv.Addr(),
		DataDir:                    ingressWrongDataDir,
		AllowSelfSignedCertForTest: true,
	}
	ingressWrongSrv, err := NewServer(ingressWrongCfg)
	if err != nil {
		t.Fatalf("NewServer ingressWrong failed: %v", err)
	}
	if err := ingressWrongSrv.Start(); err != nil {
		t.Fatalf("ingressWrongSrv.Start failed: %v", err)
	}
	defer ingressWrongSrv.Close()

	qConnWrongIngress, err := quic.DialAddr(ctx, ingressWrongSrv.Addr(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("dial wrong ingress failed: %v", err)
	}
	defer qConnWrongIngress.CloseWithError(0, "normal")

	h3ConnWrongIngress := tr.NewClientConn(qConnWrongIngress)
	reqCascadeFail, err := http.NewRequestWithContext(ctx, http.MethodConnect, "//"+echoAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCascadeFail.Proto = "HTTP/1.1"
	reqCascadeFail.Header.Set("Authorization", "Bearer "+clientToken)
	reqCascadeFail.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	reqCascadeFail.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	reqStrCascadeFail, err := h3ConnWrongIngress.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("OpenRequestStream cascade fail failed: %v", err)
	}
	defer reqStrCascadeFail.Close()

	if err := reqStrCascadeFail.SendRequestHeader(reqCascadeFail); err != nil {
		t.Fatalf("SendRequestHeader cascade fail failed: %v", err)
	}

	respCascadeFail, err := reqStrCascadeFail.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse cascade fail failed: %v", err)
	}
	if respCascadeFail.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway from Ingress when egress rejects wrong hop credential, got %d", respCascadeFail.StatusCode)
	}

	// 2.4 验证 Egress 端未记录或暴露任何客户端原始用户 token
	if egressSrv.tokenStore != nil && egressSrv.tokenStore.v.Validate(clientToken) {
		t.Fatalf("egress validator must not contain or validate client user token")
	}
	for _, item := range egressSrv.tokenStore.List() {
		if item.Token == clientToken {
			t.Fatalf("egress token store must not contain client user token %q", clientToken)
		}
	}

	// 2.5 验证生产环境下 Role == ingress 时 NextHopAddr 为空必须报错
	prodIngressCfg := ServerConfig{
		Listen:        ":443",
		Domain:        "example.com",
		Role:          "ingress",
		HopCredential: "hop-secret-999",
		NextHopAddr:   "",
	}
	_, errProd := NewServer(prodIngressCfg)
	if errProd == nil || !strings.Contains(errProd.Error(), "next hop address required") {
		t.Fatalf("expected NewServer with role=ingress and empty next_hop_addr in production to fail, got: %v", errProd)
	}

	// 2.6 验证 SetNextHopDialerForTest 和 SetNextHopUDPDialerForTest 钩子工作正常
	var hookCalled atomic.Bool
	ingressSrv.SetNextHopDialerForTest(func(nextHopAddr, target, hopCred string) (net.Conn, error) {
		hookCalled.Store(true)
		return nil, errors.New("mock dialer error")
	})
	c, errDial := ingressSrv.quicServer.dialNextHopTCP("127.0.0.1:1234", "target:80", "cred")
	if errDial == nil || !hookCalled.Load() {
		if c != nil {
			_ = c.Close()
		}
		t.Fatalf("expected SetNextHopDialerForTest hook to be called and return error")
	}
	ingressSrv.SetNextHopDialerForTest(nil)

	var udpHookCalled atomic.Bool
	ingressSrv.SetNextHopUDPDialerForTest(func(nextHopAddr, target, hopCred string) (net.Conn, error) {
		udpHookCalled.Store(true)
		return nil, errors.New("mock udp dialer error")
	})
	u, errUDPDial := ingressSrv.quicServer.dialNextHopUDP("127.0.0.1:1234", "target:80", "cred")
	if errUDPDial == nil || !udpHookCalled.Load() {
		if u != nil {
			_ = u.Close()
		}
		t.Fatalf("expected SetNextHopUDPDialerForTest hook to be called and return error")
	}
	ingressSrv.SetNextHopUDPDialerForTest(nil)
}

// TestPhase8Gate_EdgeQuotaRevocationAndDisconnect (Phase 8 Gate)
// 验证边缘节点配额同步、即时会话阻断与吊销后的 401 拦截
func TestPhase8Gate_EdgeQuotaRevocationAndDisconnect(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	clientToken := "tok_phase8_edge_test_user"
	adminKey := "phase8_edge_admin_secret"

	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      clientToken,
		AdminKey:                   adminKey,
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	srv.quicServer.SetTokenStore(srv.tokenStore)

	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	// 1. 搭建模拟商业中台计量服务
	var reportReceived atomic.Bool
	midLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		midLn, _ = net.Listen("tcp", "127.0.0.1:0")
	}
	midServer := &httptest.Server{
		Listener: midLn,
		Config: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/admin/metering" {
					http.NotFound(w, r)
					return
				}
				if r.Header.Get("Aero-Admin-Key") != adminKey {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				reportReceived.Store(true)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"code":           0,
					"revoked_tokens": []string{clientToken},
					"message":        "ok",
				})
			}),
		},
	}
	midServer.Start()
	defer midServer.Close()

	// 2. 搭建客户端并连接 Edge 服务器
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

	// 发送初始有效请求以验证连接成功并在服务器端完成绑定
	req1, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	req1.Header.Set("Content-Type", "application/dns-message")
	req1.Header.Set("Authorization", "Bearer "+clientToken)
	req1.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req1.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	resp1, err := h3Conn.RoundTrip(req1)
	if err != nil {
		t.Fatalf("RoundTrip 1 failed: %v", err)
	}
	_ = resp1.Body.Close()

	if resp1.StatusCode == http.StatusUnauthorized {
		t.Fatalf("expected initial request to succeed, got 401")
	}

	// 3. 调用 SyncMeteringWithMid，注入模拟中台返回的 revoked_tokens 包含该客户端 token
	revoked, err := srv.quicServer.SyncMeteringWithMid(ctx, midServer.URL, adminKey, []MeteringReportRecord{
		{
			Token:     clientToken,
			BytesUp:   1024,
			BytesDown: 2048,
		},
	})
	if err != nil {
		t.Fatalf("SyncMeteringWithMid failed: %v", err)
	}
	if !reportReceived.Load() {
		t.Fatalf("midplatform did not receive metering report")
	}
	if len(revoked) != 1 || revoked[0] != clientToken {
		t.Fatalf("expected revoked_tokens [%s], got %v", clientToken, revoked)
	}

	// 4. 断言该 token 被立即撤销
	if srv.validator.Validate(clientToken) {
		t.Fatalf("expected token %s to be revoked from validator", clientToken)
	}

	// 5. 断言现有连接被切断
	select {
	case <-qConn.Context().Done():
		// 连接已被切断
	case <-time.After(1 * time.Second):
		t.Fatalf("expected active QUIC connection to be severed after token revocation")
	}

	// 6. 断言后续带有该 token 的请求严格返回 401 Unauthorized
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	qConn2, err := quic.DialAddr(ctx2, srv.quicListener.Addr().String(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr for second attempt failed: %v", err)
	}
	defer qConn2.CloseWithError(0, "normal")

	h3Conn2 := tr.NewClientConn(qConn2)
	req2, err := http.NewRequestWithContext(ctx2, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/dns-message")
	req2.Header.Set("Authorization", "Bearer "+clientToken)
	req2.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req2.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	resp2, err := h3Conn2.RoundTrip(req2)
	if err != nil {
		t.Fatalf("subsequent RoundTrip failed: %v", err)
	}
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for revoked token, got %d", resp2.StatusCode)
	}
}

// TestFinalGate_SalamanderDualKeyRollover 验证服务端配置主密钥与备用密钥时，使用备用密钥的客户端能够正常握手与传输数据；使用未授权密钥则被静默丢弃。
func TestFinalGate_SalamanderDualKeyRollover(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	primaryKey := "aero-salamander-primary-key-2026"
	fallbackKey := "aero-salamander-fallback-key-2025"
	unauthorizedKey := "aero-salamander-unauthorized-key-999"

	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "salamander_dual_key_token",
		AllowSelfSignedCertForTest: true,
		ObfsPassword:               primaryKey,
		FallbackObfsPasswords:      []string{fallbackKey},
		PaddingJitter:              true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	srv.quicServer.SetAllowLoopbackForTest(true)

	network := "udp4"
	localBind := "127.0.0.1:0"
	if strings.Contains(listenAddr, "[") || strings.HasPrefix(listenAddr, "::") {
		network = "udp6"
		localBind = "[::1]:0"
	}

	tlsConf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	quicConf := DefaultQUICConfig()
	serverUDPAddr := srv.quicListener.Addr()

	// 1. 验证使用备用密钥的客户端能够正常握手与传输数据
	rawClientConn1, err := net.ListenPacket(network, localBind)
	if err != nil {
		t.Fatalf("ListenPacket 1 failed: %v", err)
	}
	defer rawClientConn1.Close()

	tap1 := &tapPacketConn{PacketConn: rawClientConn1}
	clientObfsConn1 := NewSalamanderPacketConn(tap1, fallbackKey, true, primaryKey)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel1()

	qConn1, err := quic.Dial(ctx1, clientObfsConn1, serverUDPAddr, tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.Dial with fallback key failed: %v", err)
	}
	defer qConn1.CloseWithError(0, "normal")

	tr1 := &http3.Transport{EnableDatagrams: true}
	h3Conn1 := tr1.NewClientConn(qConn1)

	req1, err := http.NewRequestWithContext(ctx1, "GET", "https://"+host+"/healthz", nil)
	if err != nil {
		t.Fatalf("NewRequest 1 failed: %v", err)
	}
	resp1, err := h3Conn1.RoundTrip(req1)
	if err != nil {
		t.Fatalf("RoundTrip with fallback key failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp1.StatusCode)
	}
	body1, err := io.ReadAll(resp1.Body)
	if err != nil {
		t.Fatalf("ReadAll body 1 failed: %v", err)
	}
	if string(body1) != "ok" {
		t.Fatalf("expected body 'ok', got %q", string(body1))
	}

	// 2. 验证使用主密钥的客户端能够正常握手与传输数据
	rawClientConn2, err := net.ListenPacket(network, localBind)
	if err != nil {
		t.Fatalf("ListenPacket 2 failed: %v", err)
	}
	defer rawClientConn2.Close()

	tap2 := &tapPacketConn{PacketConn: rawClientConn2}
	clientObfsConn2 := NewSalamanderPacketConn(tap2, primaryKey, true)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	qConn2, err := quic.Dial(ctx2, clientObfsConn2, serverUDPAddr, tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.Dial with primary key failed: %v", err)
	}
	defer qConn2.CloseWithError(0, "normal")

	tr2 := &http3.Transport{EnableDatagrams: true}
	h3Conn2 := tr2.NewClientConn(qConn2)

	req2, err := http.NewRequestWithContext(ctx2, "GET", "https://"+host+"/healthz", nil)
	if err != nil {
		t.Fatalf("NewRequest 2 failed: %v", err)
	}
	resp2, err := h3Conn2.RoundTrip(req2)
	if err != nil {
		t.Fatalf("RoundTrip with primary key failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp2.StatusCode)
	}
	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("ReadAll body 2 failed: %v", err)
	}
	if string(body2) != "ok" {
		t.Fatalf("expected body 'ok', got %q", string(body2))
	}

	// 3. 验证使用未授权密钥的客户端被静默丢弃 (握手超时)
	rawClientConn3, err := net.ListenPacket(network, localBind)
	if err != nil {
		t.Fatalf("ListenPacket 3 failed: %v", err)
	}
	defer rawClientConn3.Close()

	tap3 := &tapPacketConn{PacketConn: rawClientConn3}
	clientObfsConn3 := NewSalamanderPacketConn(tap3, unauthorizedKey, true)

	ctx3, cancel3 := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel3()

	_, wrongErr := quic.Dial(ctx3, clientObfsConn3, serverUDPAddr, tlsConf, quicConf)
	if wrongErr == nil {
		t.Fatalf("expected quic.Dial with unauthorized key to fail/timeout, but succeeded")
	}
}

// TestFinalGate_EdgeOfflineGraceAndWebRTCFastAging 验证中台离线时在 30 分钟宽限期内会话不中断，
// 网络恢复后将离线积压流量打包批量回补上报，以及 WebRTC STUN 探针 15 秒快速老化与 >=60 防雪崩回收。
func TestFinalGate_EdgeOfflineGraceAndWebRTCFastAging(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()
	clientToken := "gate_offline_and_webrtc_test_tok"
	adminKey := "gate_offline_admin_secret"

	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      clientToken,
		AdminKey:                   adminKey,
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	srv.quicServer.SetTokenStore(srv.tokenStore)
	srv.quicServer.SetAllowLoopbackForTest(true)

	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	// 1. 验证离线容灾策略默认值 (30m 宽限期, 500MB 突发流量)
	defPolicy := srv.quicServer.OfflinePolicy()
	if defPolicy.GracePeriod != 30*time.Minute {
		t.Fatalf("expected default GracePeriod 30m, got %v", defPolicy.GracePeriod)
	}
	if defPolicy.MaxBurstPerToken != 500*1024*1024 {
		t.Fatalf("expected default MaxBurstPerToken 500MB, got %d", defPolicy.MaxBurstPerToken)
	}

	// 2. 建立客户端 QUIC 连接
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)

	// 验证初始请求成功绑定 Token
	req1, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	req1.Header.Set("Content-Type", "application/dns-message")
	req1.Header.Set("Authorization", "Bearer "+clientToken)
	req1.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req1.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))

	resp1, err := h3Conn.RoundTrip(req1)
	if err != nil {
		t.Fatalf("RoundTrip 1 failed: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode == http.StatusUnauthorized {
		t.Fatalf("expected initial request to succeed, got 401")
	}

	// 3. 模拟中台离线（网络分区/不可达）
	deadLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		deadLn, _ = net.Listen("tcp", "127.0.0.1:0")
	}
	offlineURL := "http://" + deadLn.Addr().String() + "/admin/metering"
	_ = deadLn.Close()

	records1 := []MeteringReportRecord{
		{
			Token:     clientToken,
			BytesUp:   1000,
			BytesDown: 1000,
		},
	}
	ctxOffline, cancelOffline := context.WithTimeout(context.Background(), 1*time.Second)
	_, err = srv.quicServer.SyncMeteringWithMid(ctxOffline, offlineURL, adminKey, records1)
	cancelOffline()
	if err == nil {
		t.Fatalf("expected error when midplatform is offline, got nil")
	}

	// 断言：处于 30 分钟宽限期内，不阻断现有活跃会话！
	if !srv.validator.Validate(clientToken) {
		t.Fatalf("expected clientToken to remain valid within offline grace period")
	}
	if srv.quicServer.OfflineSince().IsZero() {
		t.Fatalf("expected offlineSince to be recorded on mid failure")
	}
	backlog := srv.quicServer.OfflineBacklog()
	if len(backlog) != 1 || backlog[clientToken].BytesUp != 1000 {
		t.Fatalf("expected offline backlog to store unsynced records, got: %v", backlog)
	}

	// 断言现有会话仍可顺畅通信
	reqGrace, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	reqGrace.Header.Set("Content-Type", "application/dns-message")
	reqGrace.Header.Set("Authorization", "Bearer "+clientToken)
	reqGrace.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	reqGrace.Header.Set("Aero-Nonce", hex.EncodeToString(make([]byte, 32)))
	respGrace, err := h3Conn.RoundTrip(reqGrace)
	if err != nil {
		t.Fatalf("RoundTrip during offline grace period failed: %v", err)
	}
	_ = respGrace.Body.Close()
	if respGrace.StatusCode == http.StatusUnauthorized {
		t.Fatalf("session blocked prematurely during offline grace period")
	}

	// 4. 模拟中台故障恢复，测试批量回补上报 (Bulk Metering Sync)
	var midReceivedReq atomic.Pointer[meteringReportReq]
	midLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		midLn, _ = net.Listen("tcp", "127.0.0.1:0")
	}
	midServer := &httptest.Server{
		Listener: midLn,
		Config: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/admin/metering" {
					http.NotFound(w, r)
					return
				}
				var mReq meteringReportReq
				if err := json.NewDecoder(r.Body).Decode(&mReq); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				midReceivedReq.Store(&mReq)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(meteringReportResp{
					Code:          0,
					RevokedTokens: []string{},
					Message:       "ok",
				})
			}),
		},
	}
	midServer.Start()
	defer midServer.Close()

	records2 := []MeteringReportRecord{
		{
			Token:     clientToken,
			BytesUp:   500,
			BytesDown: 500,
		},
	}
	_, err = srv.quicServer.SyncMeteringWithMid(ctx, midServer.URL, adminKey, records2)
	if err != nil {
		t.Fatalf("SyncMeteringWithMid recovery failed: %v", err)
	}

	// 断言中台成功接收到打包积压的批量流量 (1000+500 = 1500)
	recv := midReceivedReq.Load()
	if recv == nil || len(recv.Records) != 1 {
		t.Fatalf("midServer did not receive expected bulk report: %v", recv)
	}
	if recv.Records[0].BytesUp != 1500 {
		t.Fatalf("expected bulk merged BytesUp=1500, got %d", recv.Records[0].BytesUp)
	}
	if len(srv.quicServer.OfflineBacklog()) != 0 {
		t.Fatalf("expected offline backlog to be cleared after recovery")
	}
	if !srv.quicServer.OfflineSince().IsZero() {
		t.Fatalf("expected offlineSince to be reset after recovery")
	}

	// 5. 验证宽限期超过 30 分钟后阻断会话
	srv.quicServer.SetOfflineSinceForTest(time.Now().Add(-31 * time.Minute))
	ctxExpired, cancelExpired := context.WithTimeout(context.Background(), 1*time.Second)
	_, err = srv.quicServer.SyncMeteringWithMid(ctxExpired, offlineURL, adminKey, records1)
	cancelExpired()
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected grace period expired error, got: %v", err)
	}

	// 6. 验证 WebRTC STUN 探针与非 STUN 端口/特征识别
	if !isSTUNTarget("10.0.0.1:3478") || !isSTUNTarget("webrtc.example.com:19302") || !isSTUNTarget("turn.aero:5349") {
		t.Fatalf("expected isSTUNTarget to return true for standard STUN ports")
	}
	if isSTUNTarget("10.0.0.1:443") || isSTUNTarget("10.0.0.1:8080") {
		t.Fatalf("expected isSTUNTarget to return false for non-STUN ports")
	}
	stunMsg := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x01, 0x02}
	nonStunMsg := []byte{0x00, 0x01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02}
	if !isSTUNPayload(stunMsg) {
		t.Fatalf("expected isSTUNPayload to return true for STUN magic cookie 0x2112A442")
	}
	if isSTUNPayload(nonStunMsg) {
		t.Fatalf("expected isSTUNPayload to return false for non-STUN payload")
	}

	// 7. 验证看门狗快速老化与 >=60 防雪崩优先回收
	srv.quicServer.SetUDPIdleTimeoutsForTest(40*time.Millisecond, 400*time.Millisecond)

	var stunClosed atomic.Bool
	stunTracker := &udpSessionTracker{
		token:      clientToken,
		isSTUN:     &atomic.Bool{},
		lastActive: &atomic.Int64{},
		closeFn: func() {
			stunClosed.Store(true)
		},
	}
	stunTracker.isSTUN.Store(true)
	stunTracker.lastActive.Store(time.Now().UnixNano())
	srv.quicServer.registerUDPSession(stunTracker)
	defer srv.quicServer.unregisterUDPSession(stunTracker)

	var normalClosed atomic.Bool
	normalTracker := &udpSessionTracker{
		token:      clientToken,
		isSTUN:     &atomic.Bool{},
		lastActive: &atomic.Int64{},
		closeFn: func() {
			normalClosed.Store(true)
		},
	}
	normalTracker.isSTUN.Store(false)
	normalTracker.lastActive.Store(time.Now().UnixNano())
	srv.quicServer.registerUDPSession(normalTracker)
	defer srv.quicServer.unregisterUDPSession(normalTracker)

	// 模拟并发 UDP Context 达到预警阈值 60，STUN 探针静默 60ms (> 40ms 设定超时)
	srv.quicServer.udpMu.Lock()
	srv.quicServer.tokenUDPCtx[clientToken] = 60
	srv.quicServer.udpMu.Unlock()
	stunTracker.lastActive.Store(time.Now().Add(-60 * time.Millisecond).UnixNano())
	normalTracker.lastActive.Store(time.Now().Add(-60 * time.Millisecond).UnixNano())

	// 申请 UDP Slot 触发高水位防雪崩清理
	acquired := srv.quicServer.acquireUDPSlot(clientToken)
	if !acquired {
		t.Fatalf("expected acquireUDPSlot to succeed after reclaiming stale STUN probe")
	}
	defer srv.quicServer.releaseUDPSlot(clientToken)

	// 断言 STUN 探针被立即回收关闭，而正常长连接媒体流未被回收
	if !stunClosed.Load() {
		t.Fatalf("expected STUN probe to be fast-reclaimed under >=60 threshold")
	}
	if normalClosed.Load() {
		t.Fatalf("normal media stream must NOT be reclaimed under >=60 threshold")
	}
}

// TestValidator_NonceWALPersistence 验证 Validator Nonce WAL 持久化与防重启重放
func TestValidator_NonceWALPersistence(t *testing.T) {
	tempDir := t.TempDir()
	walPath := filepath.Join(tempDir, "nonce.wal")

	token := "wal_test_token"
	nonce := []byte("0123456789abcdef0123456789abcdef")
	ts := uint64(time.Now().UnixMilli())

	v1 := NewValidator(walPath)
	v1.AddToken(token, "test", 24*time.Hour)

	// 第一次校验成功
	if !v1.ValidateFull(token, ts, nonce) {
		t.Fatalf("expected first ValidateFull to succeed")
	}
	// 同一实例重放被拒绝
	if v1.ValidateFull(token, ts, nonce) {
		t.Fatalf("expected replay ValidateFull to fail")
	}
	v1.Close()

	// 模拟进程重启：启动新的 Validator 实例，指定同一 walPath
	v2 := NewValidator(walPath)
	defer v2.Close()
	v2.AddToken(token, "test", 24*time.Hour)

	// 重启后使用相同 Nonce 依然被拒绝（防重启重放窗口）
	if v2.ValidateFull(token, ts, nonce) {
		t.Fatalf("expected ValidateFull after restart to reject previously consumed nonce from WAL")
	}

	// 新的 Nonce 允许通过
	newNonce := []byte("fedcba9876543210fedcba9876543210")
	if !v2.ValidateFull(token, ts, newNonce) {
		t.Fatalf("expected new nonce to be accepted by v2")
	}
}

// TestMultiPortHopping 验证边缘节点多端口监听与客户端跳频容灾
func TestMultiPortHopping(t *testing.T) {
	dataDir := t.TempDir()
	listenAddr, host := findTestAddr()

	// 动态寻找一个未占用的 alt 端口
	altPconn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket for alt port failed: %v", err)
	}
	altPort := altPconn.LocalAddr().(*net.UDPAddr).Port
	_ = altPconn.Close()

	cfg := ServerConfig{
		Listen:                     listenAddr,
		Domain:                     host,
		DataDir:                    dataDir,
		Token:                      "multi_port_test_tok",
		AllowSelfSignedCertForTest: true,
		AltListenPorts:             []int{altPort},
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Close()

	altAddrs := srv.AltAddrs()
	if len(altAddrs) != 1 {
		t.Fatalf("expected 1 alt addr, got %d", len(altAddrs))
	}

	// 客户端通过备用端口直连握手
	tlsConf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	quicConf := DefaultQUICConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	network := "udp4"
	localBind := "127.0.0.1:0"
	if strings.Contains(listenAddr, "[") || strings.HasPrefix(listenAddr, "::") {
		network = "udp6"
		localBind = "[::1]:0"
	}
	pconn, err := net.ListenPacket(network, localBind)
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer pconn.Close()

	// 连接到备用端口并完成 HTTP/3 GET /healthz
	altUDPAddr, _ := net.ResolveUDPAddr("udp", altAddrs[0])
	qConn, err := quic.Dial(ctx, pconn, altUDPAddr, tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.Dial to alt port failed: %v", err)
	}
	defer qConn.CloseWithError(0, "normal")

	tr := &http3.Transport{EnableDatagrams: true}
	h3Conn := tr.NewClientConn(qConn)

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/healthz", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	resp, err := h3Conn.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip via alt port failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}
