// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAdversarial_IPv6Pool_Boundaries_Concurrency_DoubleRelease stress-tests
// IPv6Pool for rapid cycles, high concurrency uniqueness, exhaustion behavior,
// and double-release safety.
func TestAdversarial_IPv6Pool_Boundaries_Concurrency_DoubleRelease(t *testing.T) {
	pool, err := NewIPv6Pool("fd88::/64")
	if err != nil {
		t.Fatalf("NewIPv6Pool failed: %v", err)
	}

	// 1. Rapid sequential allocate and release cycles (10,000 cycles)
	for i := 0; i < 10000; i++ {
		p, err := pool.Allocate()
		if err != nil {
			t.Fatalf("cycle %d allocate failed: %v", i, err)
		}
		if p.Bits() != 128 || !p.Addr().Is6() {
			t.Fatalf("cycle %d invalid prefix: %v", i, p)
		}
		pool.Release(p)
	}

	// Verify pool is completely clean after 10,000 cycles
	pool.mu.Lock()
	usedCount := len(pool.used)
	pool.mu.Unlock()
	if usedCount != 0 {
		t.Fatalf("expected 0 used addresses after release, got %d", usedCount)
	}

	// 2. High-concurrency allocation with uniqueness check
	const workers = 64
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	var duplicateDetected atomic.Bool
	activeAddrs := make(map[netip.Addr]bool)
	var mapMu sync.Mutex

	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				p, err := pool.Allocate()
				if err != nil {
					t.Errorf("concurrent allocate failed: %v", err)
					return
				}

				mapMu.Lock()
				if activeAddrs[p.Addr()] {
					duplicateDetected.Store(true)
					t.Errorf("duplicate IP allocated concurrently: %v", p.Addr())
				}
				activeAddrs[p.Addr()] = true
				mapMu.Unlock()

				time.Sleep(10 * time.Microsecond)

				mapMu.Lock()
				delete(activeAddrs, p.Addr())
				mapMu.Unlock()

				pool.Release(p)
			}
		}()
	}

	wg.Wait()
	if duplicateDetected.Load() {
		t.Fatal("concurrent allocation produced duplicate IPv6 addresses")
	}

	// 3. Pool exhaustion boundary conditions
	smallPool, _ := NewIPv6Pool("fd88::/64")
	smallPool.mu.Lock()
	smallPool.maxHost = 6 // Hosts 2, 3, 4, 5 (4 addresses total)
	smallPool.mu.Unlock()

	var allocated []netip.Prefix
	for i := 0; i < 4; i++ {
		p, err := smallPool.Allocate()
		if err != nil {
			t.Fatalf("allocate %d failed: %v", i, err)
		}
		allocated = append(allocated, p)
	}

	// 5th allocation MUST fail with pool exhausted
	_, err = smallPool.Allocate()
	if err == nil {
		t.Fatal("expected error on exhausted pool, got nil")
	}

	// Release 1 address and re-allocate
	smallPool.Release(allocated[0])
	newP, err := smallPool.Allocate()
	if err != nil {
		t.Fatalf("allocation after partial release failed: %v", err)
	}
	if newP.Addr() != allocated[0].Addr() {
		t.Fatalf("expected re-allocated address %v, got %v", allocated[0].Addr(), newP.Addr())
	}

	// 4. Double-Release and Corrupted Prefix Safety
	pool.Release(allocated[0])
	pool.Release(allocated[0]) // Double release
	pool.Release(allocated[0]) // Triple release

	// Release unallocated / invalid prefixes
	unallocatedPrefix := netip.MustParsePrefix("fd88::9999/128")
	pool.Release(unallocatedPrefix)
	pool.Release(netip.Prefix{}) // zero prefix

	// Verify normal allocation still works after double releases
	pTest, err := pool.Allocate()
	if err != nil {
		t.Fatalf("allocate after double-release test failed: %v", err)
	}
	pool.Release(pTest)
}

// TestAdversarial_Edge_ICMPv6_PTB_Boundaries_And_RFC4443Checksum stress-tests
// ICMPv6 Packet Too Big generation at exact MTU boundaries and verifies RFC 4443 checksum validity.
func TestAdversarial_Edge_ICMPv6_PTB_Boundaries_And_RFC4443Checksum(t *testing.T) {
	gw := net.ParseIP("fd88::1")
	origSrc := net.ParseIP("fd88::2")
	origDst := net.ParseIP("2606:4700:4700::1111")

	// 1. Next-MTU clamping verification in buildICMPv6PacketTooBig
	testPkt := make([]byte, 1400)
	testPkt[0] = 0x60
	copy(testPkt[8:24], origSrc.To16())
	copy(testPkt[24:40], origDst.To16())

	// nextMTU < 1280 (RFC 8200 minimum MTU) must clamp to 1280
	for _, subMTU := range []uint32{0, 500, 1279} {
		ptb := buildICMPv6PacketTooBig(testPkt, gw, subMTU)
		if ptb == nil {
			t.Fatalf("buildICMPv6PacketTooBig returned nil for nextMTU=%d", subMTU)
		}
		mtuField := binary.BigEndian.Uint32(ptb[44:48])
		if mtuField != 1280 {
			t.Fatalf("expected nextMTU %d clamped to 1280, got %d", subMTU, mtuField)
		}
	}

	// nextMTU >= 1280 must be preserved exactly
	for _, validMTU := range []uint32{1280, 1360, 1361, 1500, 9000} {
		ptb := buildICMPv6PacketTooBig(testPkt, gw, validMTU)
		if ptb == nil {
			t.Fatalf("buildICMPv6PacketTooBig returned nil for nextMTU=%d", validMTU)
		}
		mtuField := binary.BigEndian.Uint32(ptb[44:48])
		if mtuField != validMTU {
			t.Fatalf("expected nextMTU %d, got %d", validMTU, mtuField)
		}
	}

	// Truncated packet (<40 bytes) must return nil without panic
	for shortLen := 0; shortLen < 40; shortLen++ {
		shortPkt := make([]byte, shortLen)
		if ptb := buildICMPv6PacketTooBig(shortPkt, gw, 1360); ptb != nil {
			t.Fatalf("expected nil for short packet length %d", shortLen)
		}
	}

	// 2. RFC 4443 Checksum verification on odd and even invoking packet lengths
	testLengths := []int{40, 41, 100, 101, 1231, 1232, 1280, 1360, 1361, 1400, 1500, 4096}
	for _, l := range testLengths {
		orig := make([]byte, l)
		orig[0] = 0x60
		copy(orig[8:24], origSrc.To16())
		copy(orig[24:40], origDst.To16())
		for k := 40; k < l; k++ {
			orig[k] = byte((k * 13) & 0xFF)
		}

		ptb := buildICMPv6PacketTooBig(orig, gw, 1360)
		if ptb == nil {
			t.Fatalf("buildICMPv6PacketTooBig failed for length %d", l)
		}

		// RFC 4443 requirement: PTB packet size must not exceed 1280 bytes
		if len(ptb) > 1280 {
			t.Fatalf("PTB packet size %d exceeds RFC 4443 1280-byte limit", len(ptb))
		}

		// Verify RFC 4443 Checksum
		csum := binary.BigEndian.Uint16(ptb[42:44])
		if csum == 0 {
			t.Fatalf("checksum is zero for length %d", l)
		}

		icmpPayloadLen := len(ptb) - 40
		pseudo := make([]byte, 40)
		copy(pseudo[0:16], gw.To16())
		copy(pseudo[16:32], origSrc.To16())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(icmpPayloadLen))
		pseudo[39] = 58 // ICMPv6 NextHeader

		var sum uint32
		addWords := func(b []byte) {
			for i := 0; i+1 < len(b); i += 2 {
				sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
			}
			if len(b)%2 == 1 {
				sum += uint32(b[len(b)-1]) << 8
			}
		}
		addWords(pseudo)
		addWords(ptb[40:])
		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
		if ^uint16(sum) != 0 {
			t.Fatalf("RFC 4443 checksum verification failed for invoking len %d (ptb len %d): sum complement=0x%04x", l, len(ptb), ^uint16(sum))
		}
	}

	// 3. Router PMTU boundary backpressure test (1360 vs 1361 bytes)
	server := NewQUICServer(nil, nil, nil, nil, nil)
	server.SetAllowLoopbackForTest(true)

	conn := newMockNATPacketConn()
	clientIPv4 := netip.MustParseAddr("10.88.0.2")
	clientIPv6 := netip.MustParseAddr("fd88::2")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router, err := NewUserSpaceNATRouter(ctx, server, "tok_boundary", clientIPv4, conn, clientIPv6)
	if err != nil {
		t.Fatalf("NewUserSpaceNATRouter failed: %v", err)
	}
	defer router.Close()
	go router.Run()

	// 3a. Packet of length 1360 (exact MTU threshold) -> MUST NOT trigger PTB
	atMTUPkt := make([]byte, 1360)
	atMTUPkt[0] = 0x60
	binary.BigEndian.PutUint16(atMTUPkt[4:6], 1320)
	atMTUPkt[6] = 17 // UDP
	copy(atMTUPkt[8:24], origSrc.To16())
	copy(atMTUPkt[24:40], origDst.To16())
	conn.inCh <- atMTUPkt

	select {
	case p := <-conn.outCh:
		if len(p) >= 48 && p[0]>>4 == 6 && p[6] == 58 && p[40] == 2 {
			t.Fatal("unexpected PTB generated for packet of exact MTU size (1360)")
		}
	case <-time.After(150 * time.Millisecond):
		// Expected: 1360 byte packet entered gVisor stack without generating local PTB
	}

	// 3b. Packet of length 1361 (1 byte over MTU threshold) -> MUST trigger PTB!
	overMTUPkt := make([]byte, 1361)
	overMTUPkt[0] = 0x60
	binary.BigEndian.PutUint16(overMTUPkt[4:6], 1321)
	overMTUPkt[6] = 17 // UDP
	copy(overMTUPkt[8:24], origSrc.To16())
	copy(overMTUPkt[24:40], origDst.To16())
	conn.inCh <- overMTUPkt

	select {
	case ptbPkt := <-conn.outCh:
		if len(ptbPkt) < 48 || ptbPkt[0]>>4 != 6 || ptbPkt[6] != 58 || ptbPkt[40] != 2 {
			t.Fatalf("expected ICMPv6 Packet Too Big for 1361-byte packet, got len=%d", len(ptbPkt))
		}
		mtu := binary.BigEndian.Uint32(ptbPkt[44:48])
		if mtu != 1360 {
			t.Fatalf("expected PTB MTU 1360, got %d", mtu)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for PTB backpressure on 1361-byte packet")
	}
}

// TestAdversarial_PureQUIC_Gate_Rejection405 verifies that TCP/443 (HTTP/1.1 and HTTP/2)
// connection attempts via Extended CONNECT or DoH are 100% rejected with HTTP 405 Method Not Allowed.
func TestAdversarial_PureQUIC_Gate_Rejection405(t *testing.T) {
	s := &Server{
		quicServer: NewQUICServer(nil, nil, nil, nil, nil),
	}

	// 1. Non-QUIC Extended CONNECT and standard CONNECT requests
	connectTests := []struct {
		name   string
		method string
		proto  string
		url    string
		header http.Header
	}{
		{
			name:   "HTTP/1.1 Standard CONNECT",
			method: http.MethodConnect,
			proto:  "HTTP/1.1",
			url:    "example.com:443",
		},
		{
			name:   "HTTP/2 Extended CONNECT connect-ip",
			method: http.MethodConnect,
			proto:  "HTTP/2.0",
			url:    "/connect-ip",
			header: http.Header{
				":protocol": []string{"connect-ip"},
			},
		},
		{
			name:   "HTTP/2 CONNECT arbitrary target",
			method: http.MethodConnect,
			proto:  "HTTP/2.0",
			url:    "8.8.8.8:443",
		},
		{
			name:   "TCP DoH POST /dns-query",
			method: http.MethodPost,
			proto:  "HTTP/1.1",
			url:    "/dns-query",
		},
		{
			name:   "HTTP/2 DoH POST /dns-query",
			method: http.MethodPost,
			proto:  "HTTP/2.0",
			url:    "/dns-query",
		},
	}

	for _, tc := range connectTests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, bytes.NewReader([]byte{0, 1, 2, 3}))
			if tc.header != nil {
				req.Header = tc.header
			}
			rec := httptest.NewRecorder()

			// Execute ServeHTTP without quicConnKey{}
			s.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected HTTP 405 Method Not Allowed for %s, got %d", tc.name, rec.Code)
			}
		})
	}

	// 2. High concurrency non-QUIC request flood (50 parallel workers)
	const concurrentFlood = 50
	var wg sync.WaitGroup
	wg.Add(concurrentFlood)

	var non405Count atomic.Int64

	for i := 0; i < concurrentFlood; i++ {
		go func(idx int) {
			defer wg.Done()
			var req *http.Request
			if idx%2 == 0 {
				req = httptest.NewRequest(http.MethodConnect, "/connect-ip", nil)
			} else {
				req = httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{1, 2}))
			}
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				non405Count.Add(1)
			}
		}(i)
	}

	wg.Wait()
	if non405Count.Load() > 0 {
		t.Fatalf("detected %d non-405 responses during pure QUIC gate flood", non405Count.Load())
	}

	// 3. Legitimate QUIC request (with quicConnKey{} in context)
	// Must NOT return 405 Method Not Allowed!
	quicReq := httptest.NewRequest(http.MethodConnect, "/connect-ip", nil)
	quicCtx := context.WithValue(quicReq.Context(), quicConnKey{}, struct{}{})
	quicReq = quicReq.WithContext(quicCtx)

	quicRec := httptest.NewRecorder()
	s.ServeHTTP(quicRec, quicReq)

	// Since quicServer.ServeDefault runs without valid auth token, it returns 401 or 400, NEVER 405
	if quicRec.Code == http.StatusMethodNotAllowed {
		t.Fatal("legitimate QUIC request was erroneously blocked by 405 gate")
	}
}
