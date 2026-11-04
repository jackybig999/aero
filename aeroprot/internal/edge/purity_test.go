// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPurityEngine_CleanScore100(t *testing.T) {
	// 1. Mock YouTube: clean US
	mockYT := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><script>var x = {"INNERTUBE_CONTEXT_GL":"US"};</script></html>`))
	}))
	defer mockYT.Close()

	// 2. Mock Google: clean 200 without HK redirect
	mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`search results`))
	}))
	defer mockGoogle.Close()

	// 3. Mock Gemini: native 200 USA
	mockGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`,2,1,200,"USA"`))
	}))
	defer mockGemini.Close()

	// 4. Mock Cloudflare: trace loc=US
	mockCF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fl=123\nloc=US\nwarp=off\n"))
	}))
	defer mockCF.Close()

	engine := NewPurityEngine("127.0.0.1:59999") // closed port for WARP
	engine.SetTestEndpoints(mockYT.URL, mockGoogle.URL, mockGemini.URL, mockCF.URL)

	report, err := engine.Probe(context.Background(), true)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}

	if report.Score != 100 {
		t.Errorf("expected Score 100, got %d", report.Score)
	}
	if report.IsCNMarked {
		t.Errorf("expected IsCNMarked false, got true")
	}
	if !report.GoogleClean {
		t.Errorf("expected GoogleClean true, got false")
	}
	if !report.CFClean {
		t.Errorf("expected CFClean true, got false")
	}
	if !report.NativeGeminiOK {
		t.Errorf("expected NativeGeminiOK true, got false")
	}
	if report.YouTubeLoc != "US" {
		t.Errorf("expected YouTubeLoc 'US', got %q", report.YouTubeLoc)
	}
	if report.IPCountry != "US" {
		t.Errorf("expected IPCountry 'US', got %q", report.IPCountry)
	}
}

func TestPurityEngine_CNMarked_And_WARPRescue(t *testing.T) {
	// 1. Mock YouTube: returns www.google.cn
	mockYT := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Redirected to www.google.cn</body></html>`))
	}))
	defer mockYT.Close()

	// 2. Mock Google: redirects to google.com.hk
	mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.google.com.hk/search?q=aero", http.StatusFound)
	}))
	defer mockGoogle.Close()

	// 3. Mock Gemini: 403 Forbidden
	mockGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`Access denied`))
	}))
	defer mockGemini.Close()

	// 4. Mock Cloudflare trace
	mockCF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("loc=HK\nwarp=off\n"))
	}))
	defer mockCF.Close()

	// Start a mock SOCKS5 listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock socks5: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSOCKS5WithWarpOn(conn)
		}
	}()

	engine := NewPurityEngine(ln.Addr().String())
	engine.SetTestEndpoints(mockYT.URL, mockGoogle.URL, mockGemini.URL, mockCF.URL)

	report, err := engine.Probe(context.Background(), true)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}

	if !report.IsCNMarked {
		t.Errorf("expected IsCNMarked true for CN YouTube & HK redirect, got false")
	}
	if !report.WARPRunning {
		t.Errorf("expected WARPRunning true, got false")
	}
	if !report.WARPGeminiOK {
		t.Errorf("expected WARPGeminiOK true, got false")
	}
	if !report.GeminiOK {
		t.Errorf("expected GeminiOK true via WARP rescue, got false")
	}
	if !report.IsWARPEgress {
		t.Errorf("expected IsWARPEgress true, got false")
	}
	if report.Score != 95 {
		t.Errorf("expected Score bumped to 95 by WARP rescue, got %d", report.Score)
	}
}

// handleMockSOCKS5WithWarpOn implements RFC 1928 SOCKS5 handshake returning warp=on for trace
func handleMockSOCKS5WithWarpOn(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 256)
	// Read greeting
	if _, err := c.Read(buf); err != nil {
		return
	}
	// Reply: version 5, no auth
	_, _ = c.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err := c.Read(buf)
	if err != nil || n < 4 {
		return
	}
	// Reply: success
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x00})

	// If HTTP GET received, return mock response
	reqBuf := make([]byte, 1024)
	rn, err := c.Read(reqBuf)
	if err != nil {
		return
	}
	reqStr := string(reqBuf[:rn])
	if reqStr != "" {
		body := "fl=456\nloc=US\nwarp=on\n"
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		_, _ = c.Write([]byte(resp))
	}
}

func TestPurityEngine_CacheAndSingleflight(t *testing.T) {
	var probeCount atomic.Int32

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeCount.Add(1)
		time.Sleep(30 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`loc=US`))
	}))
	defer mockServer.Close()

	engine := NewPurityEngine("127.0.0.1:59999")
	engine.SetTestEndpoints(mockServer.URL, mockServer.URL, mockServer.URL, mockServer.URL)

	// Concurrently invoke Probe 5 times
	var wg sync.WaitGroup
	var reports [5]*PurityReport
	for i := 0; i < 5; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			r, err := engine.Probe(context.Background(), false)
			if err == nil {
				reports[idx] = r
			}
		}()
	}
	wg.Wait()

	// All 5 should have succeeded with the same report
	for i := 0; i < 5; i++ {
		if reports[i] == nil {
			t.Fatalf("report[%d] was nil", i)
		}
	}

	// Singleflight deduplication ensures only 1 round of requests was dispatched
	// 4 endpoints sampled in 1 probe = ~4 requests
	cnt := probeCount.Load()
	if cnt > 5 {
		t.Errorf("expected <= 5 server calls due to singleflight deduplication, got %d", cnt)
	}
}

func TestPurityReport_WireContract_Strict(t *testing.T) {
	// Test camelCase UnmarshalJSON support per Rule 16 & Rule 21
	camelJSON := `{
		"purityScore": 95,
		"ipCountry": "US",
		"youtubeLoc": "US",
		"googleClean": true,
		"googleHkRedirect": false,
		"cfClean": true,
		"nativeGeminiOk": false,
		"geminiCountry": "USA",
		"warpInstalled": true,
		"warpRunning": true,
		"warpGeminiOk": true,
		"geminiOk": true,
		"isCnMarked": true,
		"isRegionMismatched": false,
		"aiBlocked": false,
		"isWarpEgress": true
	}`

	var r PurityReport
	if err := json.Unmarshal([]byte(camelJSON), &r); err != nil {
		t.Fatalf("unmarshal camelCase JSON: %v", err)
	}

	if r.Score != 95 {
		t.Errorf("expected Score 95, got %d", r.Score)
	}
	if r.IPCountry != "US" {
		t.Errorf("expected IPCountry 'US', got %q", r.IPCountry)
	}
	if !r.GoogleClean {
		t.Errorf("expected GoogleClean true")
	}
	if !r.CFClean {
		t.Errorf("expected CFClean true")
	}
	if !r.WARPRunning {
		t.Errorf("expected WARPRunning true")
	}
	if !r.IsWARPEgress {
		t.Errorf("expected IsWARPEgress true")
	}
}

func TestEvaluatePurityReport_IdempotencyAndRegionMismatch(t *testing.T) {
	// Subtest 1: Region mismatch must evaluate to identical score on call 1 and call 2
	rMismatch := &PurityReport{
		IPCountry:      "DE",
		YouTubeLoc:     "US",
		GoogleClean:    true,
		CFClean:        true,
		NativeGeminiOK: true,
	}
	EvaluatePurityReport(rMismatch)
	score1 := rMismatch.Score
	if !rMismatch.IsRegionMismatched {
		t.Fatalf("expected IsRegionMismatched true, got false")
	}
	if score1 != 80 {
		t.Fatalf("expected score 80 for region mismatch, got %d", score1)
	}

	EvaluatePurityReport(rMismatch)
	score2 := rMismatch.Score
	if score2 != score1 {
		t.Fatalf("NON-IDEMPOTENT SCORING: call 1 = %d, call 2 = %d", score1, score2)
	}

	// Subtest 2: Clean matched report must evaluate to 100 on both calls
	rClean := &PurityReport{
		IPCountry:      "US",
		YouTubeLoc:     "US",
		GoogleClean:    true,
		CFClean:        true,
		NativeGeminiOK: true,
	}
	EvaluatePurityReport(rClean)
	if rClean.Score != 100 || rClean.IsRegionMismatched {
		t.Fatalf("expected score 100 and IsRegionMismatched false, got score=%d, mismatched=%v",
			rClean.Score, rClean.IsRegionMismatched)
	}
	EvaluatePurityReport(rClean)
	if rClean.Score != 100 || rClean.IsRegionMismatched {
		t.Fatalf("NON-IDEMPOTENT SCORING on clean report: score=%d", rClean.Score)
	}

	// Subtest 3: Dynamic state recovery: if mismatch is resolved, re-evaluation clears mismatch
	rMismatch.IPCountry = "US" // Now matches YouTubeLoc "US"
	EvaluatePurityReport(rMismatch)
	if rMismatch.IsRegionMismatched {
		t.Fatalf("expected IsRegionMismatched to reset to false after IPCountry updated to match YouTubeLoc")
	}
	if rMismatch.Score != 100 {
		t.Fatalf("expected score to recover to 100, got %d", rMismatch.Score)
	}
}
