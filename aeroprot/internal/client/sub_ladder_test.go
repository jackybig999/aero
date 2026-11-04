// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Feature 17: Client Ladder Concurrent Port Probing Tests
// ============================================================================

func TestFetchSubscription_Ladder_443NormalPath(t *testing.T) {
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()

	var candPortProbed atomic.Int32
	var normal443Probed atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if strings.Contains(host, ":") {
			candPortProbed.Add(1)
		} else {
			normal443Probed.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"version": "aero/3.0",
			"userId": "admin",
			"servers": [
				{"name": "primary-node", "address": "primary.aero.test:443", "token": "tok_primary"}
			]
		}`)
	})

	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	sub, err := FetchSubscription(context.Background(), "http://primary.aero.test/sub/admin", SubFetchOptions{DisableCache: true})
	if err != nil {
		t.Fatalf("expected successful 443 fetch, got: %v", err)
	}
	if len(sub.Servers) != 1 || sub.Servers[0].Address != "primary.aero.test:443" {
		t.Fatalf("unexpected server in response: %+v", sub.Servers)
	}

	if candPortProbed.Load() != 0 {
		t.Errorf("candidate ports should NOT be probed on 443 success, got %d probes", candPortProbed.Load())
	}
	if normal443Probed.Load() == 0 {
		t.Errorf("primary 443 should have been probed at least once")
	}

	cachedPort, ok := GetCachedSubPort("primary.aero.test")
	if !ok || cachedPort != 443 {
		t.Errorf("expected cached port 443, got %d (cached=%v)", cachedPort, ok)
	}
}

func TestFetchSubscription_Ladder_CandidatePortFallback_Tier1(t *testing.T) {
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if strings.Contains(host, ":8443") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"version": "aero/3.0",
				"userId": "admin",
				"servers": [
					{"name": "tier1-node", "address": "fallback-tier1.aero.test:8443", "token": "tok_8443"}
				]
			}`)
			return
		}
		// 443 and earlier candidates (2083, 2087) return 404
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "<html>404 Not Found</html>")
	})

	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	sub, err := FetchSubscription(context.Background(), "http://fallback-tier1.aero.test/sub/admin", SubFetchOptions{DisableCache: true})
	if err != nil {
		t.Fatalf("expected fallback to port 8443 to succeed, got: %v", err)
	}
	if len(sub.Servers) != 1 || sub.Servers[0].Address != "fallback-tier1.aero.test:8443" {
		t.Fatalf("unexpected server: %+v", sub.Servers)
	}

	cachedPort, ok := GetCachedSubPort("fallback-tier1.aero.test")
	if !ok || cachedPort != 8443 {
		t.Errorf("expected cached port 8443, got %d (cached=%v)", cachedPort, ok)
	}
}

func TestFetchSubscription_Ladder_CandidatePortFallback_Tier2(t *testing.T) {
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if strings.Contains(host, ":24443") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"version": "aero/3.0",
				"userId": "admin",
				"servers": [
					{"name": "tier2-node", "address": "fallback-tier2.aero.test:24443", "token": "tok_24443"}
				]
			}`)
			return
		}
		// 443 and all other candidate ports return 503
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	start := time.Now()
	sub, err := FetchSubscription(context.Background(), "http://fallback-tier2.aero.test/sub/admin", SubFetchOptions{DisableCache: true})
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("expected fallback to Tier 2 port 24443 to succeed, got: %v", err)
	}
	if len(sub.Servers) != 1 || sub.Servers[0].Address != "fallback-tier2.aero.test:24443" {
		t.Fatalf("unexpected server: %+v", sub.Servers)
	}

	if duration > 2000*time.Millisecond {
		t.Errorf("expected concurrent staggered probe to finish under 2000ms, took %v", duration)
	}

	cachedPort, ok := GetCachedSubPort("fallback-tier2.aero.test")
	if !ok || cachedPort != 24443 {
		t.Errorf("expected cached port 24443, got %d (cached=%v)", cachedPort, ok)
	}
}

func TestFetchSubscription_Ladder_InMemoryCacheReuseAndEviction(t *testing.T) {
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()

	var activePort atomic.Int32
	activePort.Store(8443)

	var calls443 atomic.Int32
	var calls8443 atomic.Int32
	var calls2083 atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if !strings.Contains(host, ":") {
			calls443.Add(1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.Contains(host, ":8443") {
			calls8443.Add(1)
			if activePort.Load() == 8443 {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"version":"aero/3.0","userId":"u1","servers":[{"name":"n8443","address":"cache.aero.test:8443","token":"tok_8443"}]}`)
				return
			}
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if strings.Contains(host, ":2083") {
			calls2083.Add(1)
			if activePort.Load() == 2083 {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"version":"aero/3.0","userId":"u1","servers":[{"name":"n2083","address":"cache.aero.test:2083","token":"tok_2083"}]}`)
				return
			}
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	// Step 1: Initial fetch discovers 8443
	sub1, err := FetchSubscription(context.Background(), "http://cache.aero.test/sub/admin", SubFetchOptions{DisableCache: true})
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if sub1.Servers[0].Address != "cache.aero.test:8443" {
		t.Fatalf("expected server on 8443, got %s", sub1.Servers[0].Address)
	}
	cached, ok := GetCachedSubPort("cache.aero.test")
	if !ok || cached != 8443 {
		t.Fatalf("expected port 8443 cached, got %d", cached)
	}

	// Step 2: Second fetch hits 8443 directly via fast path (zero 443 calls)
	init443Calls := calls443.Load()
	sub2, err := FetchSubscription(context.Background(), "http://cache.aero.test/sub/admin", SubFetchOptions{DisableCache: true})
	if err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	if sub2.Servers[0].Address != "cache.aero.test:8443" {
		t.Fatalf("expected cached port 8443 used, got %s", sub2.Servers[0].Address)
	}
	if calls443.Load() != init443Calls {
		t.Errorf("cached fast path should not call 443, before=%d, after=%d", init443Calls, calls443.Load())
	}

	// Step 3: Server relocates port to 2083. Cached 8443 fails -> evicted -> ladder probe discovers 2083
	activePort.Store(2083)
	sub3, err := FetchSubscription(context.Background(), "http://cache.aero.test/sub/admin", SubFetchOptions{DisableCache: true})
	if err != nil {
		t.Fatalf("third fetch (port migration) failed: %v", err)
	}
	if sub3.Servers[0].Address != "cache.aero.test:2083" {
		t.Fatalf("expected rediscovered port 2083, got %s", sub3.Servers[0].Address)
	}
	cachedNow, _ := GetCachedSubPort("cache.aero.test")
	if cachedNow != 2083 {
		t.Errorf("expected updated cache to 2083, got %d", cachedNow)
	}
}

func TestFetchSubscription_Ladder_AllPortsBlocked(t *testing.T) {
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	start := time.Now()
	sub, err := FetchSubscription(context.Background(), "http://blocked.aero.test/sub/admin", SubFetchOptions{DisableCache: true})
	duration := time.Since(start)

	if err == nil {
		t.Fatalf("expected error when all ports blocked, got sub: %+v", sub)
	}
	if !strings.Contains(err.Error(), "ladder probe exhausted across all candidate ports") {
		t.Errorf("expected 'ladder probe exhausted across all candidate ports' in error, got: %v", err)
	}
	if duration > 6500*time.Millisecond {
		t.Errorf("expected bounded timeout (< 6.5s), took %v", duration)
	}
}

func TestFetchSubscription_Ladder_RaceAndGoroutineLeak(t *testing.T) {
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if strings.Contains(host, ":2083") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"version":"aero/3.0","userId":"u","servers":[{"name":"s","address":"%s","token":"tok_race"}]}`, host)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	const concurrency = 20
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer wg.Done()
			urlStr := fmt.Sprintf("http://host-%d.aero.test/sub/user%d", id, id)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			sub, err := FetchSubscription(ctx, urlStr, SubFetchOptions{DisableCache: true})
			if err != nil {
				t.Errorf("goroutine %d failed: %v", id, err)
				return
			}
			if len(sub.Servers) == 0 {
				t.Errorf("goroutine %d got empty servers", id)
			}
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// Feature 18: SPKI Pin Clearing on Apply Tests
// ============================================================================

func TestClearPins_OnApply(t *testing.T) {
	ClearPins()
	if GetPinsCount() != 0 {
		t.Fatalf("initial pins count should be 0")
	}

	AddPins("HISTORICAL_PIN_1", "HISTORICAL_PIN_2")
	if GetPinsCount() != 2 {
		t.Fatalf("expected 2 pins after AddPins, got %d", GetPinsCount())
	}

	eng := NewEngine()
	eng.listenAddr = "127.0.0.1:0"

	// Subscription A arrives with its own pin
	subA := &Applied{
		Servers: []ServerConfig{{
			Name:    "node-a",
			Address: "127.0.0.1:18081",
			Token:   "tok_a",
			PinSPKI: []string{"PIN_SUB_A"},
		}},
		AllPins: []string{"PIN_SUB_A"},
	}

	err := eng.Apply(subA)
	if err != nil {
		t.Fatalf("Apply(subA) failed: %v", err)
	}

	// Historical pins must have been purged by ClearPins() inside Apply()
	pins := GetPins()
	if len(pins) != 1 || pins[0] != "PIN_SUB_A" {
		t.Fatalf("expected only PIN_SUB_A to remain, got %v", pins)
	}

	// Subscription B arrives with NO pins (standard CA validation)
	subB := &Applied{
		Servers: []ServerConfig{{
			Name:    "node-b",
			Address: "127.0.0.1:18082",
			Token:   "tok_b",
			PinSPKI: nil,
		}},
		AllPins: nil,
	}

	err = eng.Apply(subB)
	if err != nil {
		t.Fatalf("Apply(subB) failed: %v", err)
	}

	if GetPinsCount() != 0 {
		t.Fatalf("expected 0 pins after applying sub with no pins, got %d: %v", GetPinsCount(), GetPins())
	}
}

// ============================================================================
// Feature 20 & Contract Formatting Tests
// ============================================================================

func TestFormatZeroPortSubURL_ClientContract(t *testing.T) {
	cases := []struct {
		host     string
		slug     string
		expected string
	}{
		{"example.com", "admin", "https://example.com/sub/admin"},
		{"example.com:8443", "admin", "https://example.com/sub/admin"},
		{"http://example.com:2083/path", "/jacky888", "https://example.com/sub/jacky888"},
		{"https://[2001:db8::1]:2087/sub/old", "user123", "https://[2001:db8::1]/sub/user123"},
		{"192.168.1.1:10443", "superadmin", "https://192.168.1.1/sub/superadmin"},
		{"", "admin", "https://127.0.0.1/sub/admin"},
	}

	for _, tc := range cases {
		out := FormatZeroPortSubURL(tc.host, tc.slug)
		if out != tc.expected {
			t.Errorf("FormatZeroPortSubURL(%q, %q) = %q, expected %q", tc.host, tc.slug, out, tc.expected)
		}
		// Invariant: MUST NOT contain non-standard port
		if strings.Contains(out, ":8443") || strings.Contains(out, ":2083") || strings.Contains(out, ":2087") || strings.Contains(out, ":10443") {
			t.Errorf("URL contains non-standard port: %s", out)
		}
	}
}

func TestRenderNodeBadges(t *testing.T) {
	// 1. Full badge scenario
	badges := RenderNodeBadges("US", 95, false, true)
	if !strings.Contains(badges, "[🇺🇸 原生]") || !strings.Contains(badges, "[✨ Gemini 解锁]") || !strings.Contains(badges, "[🛡️ WARP 接管]") {
		t.Errorf("rendered badges missing required badges: %s", badges)
	}

	// 2. HK native only
	hkBadges := RenderNodeBadgesSlice("HK", 50, true, false)
	if len(hkBadges) != 1 || hkBadges[0] != "[🇭🇰 原生]" {
		t.Errorf("expected only HK native, got: %v", hkBadges)
	}

	// 3. JP native + Gemini unlock
	jpBadges := RenderNodeBadges("JP", 85, false, false)
	if !strings.Contains(jpBadges, "[🇯🇵 原生]") || !strings.Contains(jpBadges, "[✨ Gemini 解锁]") {
		t.Errorf("expected JP native and Gemini unlock, got: %s", jpBadges)
	}
	if strings.Contains(jpBadges, "[🛡️ WARP 接管]") {
		t.Errorf("unexpected WARP badge in %s", jpBadges)
	}
}

// ============================================================================
// Feature 19: Client DNS Zero-Leak & STUN Guardrails Tests
// ============================================================================

func TestDNSFunnel_TwoStageRouting(t *testing.T) {
	split := NewSplitEngine()
	handler := NewDNSHandler(split)

	// Injected physical DNS dialer for testing .cn passthrough
	var physicalDNSCalled atomic.Bool
	handler.SetPhysicalDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		physicalDNSCalled.Store(true)
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			buf := make([]byte, 512)
			n, _ := c2.Read(buf)
			if n > 12 {
				// Mock DNS response
				resp := make([]byte, n)
				copy(resp, buf[:n])
				resp[2] |= 0x80 // QR=1
				c2.Write(resp)
			}
		}()
		return c1, nil
	})

	// 1. Domestic .cn query (Type A) routes to physical DNS
	cnQuery := make([]byte, 30)
	cnQuery[0], cnQuery[1] = 0x12, 0x34 // Transaction ID
	// Encode "baidu.cn"
	name := "\x05baidu\x02cn\x00"
	copy(cnQuery[12:], []byte(name))
	pos := 12 + len(name)
	binary.BigEndian.PutUint16(cnQuery[pos:], 1) // Type A

	respCN := handler.HandleQuery(cnQuery, net.ParseIP("127.0.0.1"), 54321)
	if respCN == nil {
		t.Fatalf("expected response for .cn query")
	}
	if !physicalDNSCalled.Load() {
		t.Errorf("expected physical DNS dialer to be invoked for .cn domain")
	}

	// 2. Domestic .cn query (Type AAAA) returns empty response (NOERROR, 0 answer)
	cnAAAAQuery := make([]byte, 30)
	cnAAAAQuery[0], cnAAAAQuery[1] = 0x56, 0x78
	copy(cnAAAAQuery[12:], []byte(name))
	binary.BigEndian.PutUint16(cnAAAAQuery[pos:], 28) // Type AAAA

	respAAAA := handler.HandleQuery(cnAAAAQuery, net.ParseIP("127.0.0.1"), 54321)
	if respAAAA == nil {
		t.Fatalf("expected empty response for AAAA, got nil")
	}
	ancount := binary.BigEndian.Uint16(respAAAA[6:8])
	if ancount != 0 {
		t.Errorf("expected ANCOUNT=0 for dropped AAAA, got %d", ancount)
	}

	// 3. Overseas domain (google.com Type A) returns 198.18 Fake-IP without calling physical DNS
	physicalDNSCalled.Store(false)
	intlQuery := make([]byte, 30)
	intlQuery[0], intlQuery[1] = 0x9A, 0xBC
	intlName := "\x06google\x03com\x00"
	copy(intlQuery[12:], []byte(intlName))
	posIntl := 12 + len(intlName)
	binary.BigEndian.PutUint16(intlQuery[posIntl:], 1) // Type A

	respIntl := handler.HandleQuery(intlQuery, net.ParseIP("127.0.0.1"), 54321)
	if respIntl == nil {
		t.Fatalf("expected Fake-IP response for overseas query")
	}
	if physicalDNSCalled.Load() {
		t.Errorf("physical DNS should NOT be invoked for overseas domain (leak!)")
	}
	if len(respIntl) < 32 {
		t.Fatalf("response too short: %d bytes", len(respIntl))
	}
	// Verify Fake-IP starts with 198.18
	ip := net.IP(respIntl[len(respIntl)-4:])
	if !strings.HasPrefix(ip.String(), "198.18.") {
		t.Errorf("expected Fake-IP from 198.18.0.0/15 pool, got: %s", ip.String())
	}
}

func TestWebRTC_STUNPhysicalBlocking(t *testing.T) {
	// Construct RFC 5389/8489 STUN Binding Request packet
	stunPacket := make([]byte, 20)
	stunPacket[0] = 0x00                                    // Leading bits 00
	stunPacket[1] = 0x01                                    // Binding Request
	binary.BigEndian.PutUint16(stunPacket[2:4], 0)          // Length 0
	binary.BigEndian.PutUint32(stunPacket[4:8], 0x2112A442) // Magic Cookie
	// 12-byte Transaction ID
	for i := 8; i < 20; i++ {
		stunPacket[i] = byte(i)
	}

	if !isSTUNPacket(stunPacket) {
		t.Fatalf("valid STUN binding request packet was not recognized")
	}

	// Non-STUN packet with wrong magic cookie
	corruptPacket := make([]byte, 20)
	copy(corruptPacket, stunPacket)
	binary.BigEndian.PutUint32(corruptPacket[4:8], 0x11223344)
	if isSTUNPacket(corruptPacket) {
		t.Errorf("corrupt packet was incorrectly identified as STUN")
	}

	// Truncated packet
	if isSTUNPacket(stunPacket[:16]) {
		t.Errorf("truncated packet (< 20 bytes) should not be identified as STUN")
	}

	// Non-STUN header bits
	nonZeroHeader := make([]byte, 20)
	copy(nonZeroHeader, stunPacket)
	nonZeroHeader[0] = 0xC0
	if isSTUNPacket(nonZeroHeader) {
		t.Errorf("packet with leading bits 11 should not be identified as STUN")
	}
}
