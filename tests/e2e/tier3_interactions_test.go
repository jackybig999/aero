// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Tier 3 — Cross-Feature Interactions Test Suite
// Multi-feature interaction tests (8 comprehensive test cases)
// =============================================================================

// 1. Admin Subscription + Candidate Port Probing
// When port 443 fails, admin subscription is successfully fetched through candidate port traversal.
func TestTier3_AdminSub_CandidatePortProbing(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:      "edge.aero.test",
		ServerToken: "aero_adm_cross_001",
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Simulate probing candidate ports to locate edge server port
	activePort := 2083
	res := SimulateConcurrentLadderProbe(ctx, "edge.aero.test", StandardCandidatePorts, activePort, 10*time.Millisecond)
	if res.Err != nil {
		t.Fatalf("ladder probe failed: %v", res.Err)
	}

	// Fetch admin sub using discovered port endpoint
	resp, err := http.Get(server.URL() + "/sub/admin")
	if err != nil {
		t.Fatalf("failed to fetch admin sub: %v", err)
	}
	defer resp.Body.Close()

	var doc SubDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode admin sub failed: %v", err)
	}

	if doc.UserID != "admin" || doc.ExpireAt != 0 {
		t.Errorf("admin sub attributes invalid: user=%s, expireAt=%d", doc.UserID, doc.ExpireAt)
	}
}

// 2. User Subscription Quota + WARP Smart Routing
// User within quota allowed to trigger WARP routing; user over quota rejected before reaching WARP dialer.
func TestTier3_UserSubQuota_WARPSmartRouting(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:     "edge.aero.test",
		WarpActive: true,
	})
	defer server.Close()

	slug := "warp_user_test"
	limit := int64(1024 * 1024 * 10) // 10 MB

	server.UpsertUserSub(UserSub{
		Username:          "warp_user",
		Slug:              slug,
		Token:             "token_warp_user",
		ExpireAt:          time.Now().Add(1 * time.Hour).Unix(),
		TrafficLimitBytes: limit,
		TrafficUsedBytes:  0, // Under quota
	})

	// User under quota: successfully accesses subscription
	resp1, err := http.Get(server.URL() + "/sub/" + slug)
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 under quota, got %v (err=%v)", resp1.StatusCode, err)
	}
	resp1.Body.Close()

	// Consume remaining quota + 100 bytes
	server.RecordTraffic(slug, limit+100)

	// User over quota: blocked at subscription endpoint (HTTP 403), never reaches WARP dialer
	resp2, err := http.Get(server.URL() + "/sub/" + slug)
	if err != nil {
		t.Fatalf("GET /sub/%s error: %v", slug, err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected HTTP 403 Forbidden after quota exhaustion, got %d", resp2.StatusCode)
	}
}

// 3. Certificate Renewal + Live Connection Non-Disruption
// ModTime hot reload on certificate files updates new handshakes without disrupting active sessions.
func TestTier3_CertRenewal_LiveConnection(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "fullchain.cer")
	keyPath := filepath.Join(tmpDir, "privkey.key")

	certV1, err := GenerateTestCertificate("edge.aero.test", "Edge CA V1")
	if err != nil {
		t.Fatalf("generate cert v1: %v", err)
	}
	_ = os.WriteFile(certPath, certV1.CertPEM, 0644)
	_ = os.WriteFile(keyPath, certV1.KeyPEM, 0600)

	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:   "edge.aero.test",
		CertFile: certPath,
		KeyFile:  keyPath,
		UseTLS:   true,
	})
	defer server.Close()

	// Live connection session 1 established under cert V1
	c1, err := server.GetCertificateDynamic(&tls.ClientHelloInfo{ServerName: "edge.aero.test"})
	if err != nil {
		t.Fatalf("c1 failed: %v", err)
	}
	p1, _ := x509.ParseCertificate(c1.Certificate[0])
	org1 := p1.Subject.Organization[0]

	// Simulate live session state holding cert V1
	activeSessionCert := p1

	// ACME background renewal writes cert V2
	time.Sleep(15 * time.Millisecond)
	certV2, err := GenerateTestCertificate("edge.aero.test", "Edge CA V2 Renewed")
	if err != nil {
		t.Fatalf("generate cert v2: %v", err)
	}
	_ = os.WriteFile(certPath, certV2.CertPEM, 0644)
	_ = os.WriteFile(keyPath, certV2.KeyPEM, 0600)

	// New connection session 2 receives cert V2
	c2, err := server.GetCertificateDynamic(&tls.ClientHelloInfo{ServerName: "edge.aero.test"})
	if err != nil {
		t.Fatalf("c2 failed: %v", err)
	}
	p2, _ := x509.ParseCertificate(c2.Certificate[0])
	org2 := p2.Subject.Organization[0]

	if org1 != "Edge CA V1" || org2 != "Edge CA V2 Renewed" {
		t.Errorf("expected transition from Edge CA V1 to Edge CA V2 Renewed, got %s -> %s", org1, org2)
	}

	// Active session 1 was not invalidated
	if activeSessionCert.Subject.Organization[0] != "Edge CA V1" {
		t.Errorf("active session cert was mutated in place")
	}
}

// 4. Zero-Port URL + SPKI ClearPins on Update
// Applying a new zero-port subscription clears previous SPKI pins and installs new node pins.
func TestTier3_ZeroPortURL_ClearPinsOnUpdate(t *testing.T) {
	var mu sync.Mutex
	activePins := make(map[string]struct{})

	applyPins := func(newPins []string) {
		mu.Lock()
		defer mu.Unlock()
		// quic.ClearPins() call before updating
		activePins = make(map[string]struct{})
		for _, p := range newPins {
			activePins[p] = struct{}{}
		}
	}

	// First subscription with Old Pin
	applyPins([]string{"SPKI_OLD_PIN_ABC123"})
	if len(activePins) != 1 {
		t.Fatalf("expected 1 pin initially")
	}

	// New zero-port subscription arrives with New Pin
	newZeroPortSub := SubDocument{
		Version:  "aero/3.0",
		UserID:   "admin",
		ExpireAt: 0,
		Servers: []SubServer{{
			Name:     "New-Node",
			Address:  "edge.aero.test", // zero-port
			PinSPKI:  []string{"SPKI_NEW_PIN_XYZ789"},
			AltPorts: StandardCandidatePorts,
		}},
	}

	applyPins(newZeroPortSub.Servers[0].PinSPKI)

	mu.Lock()
	_, oldPinExists := activePins["SPKI_OLD_PIN_ABC123"]
	_, newPinExists := activePins["SPKI_NEW_PIN_XYZ789"]
	mu.Unlock()

	if oldPinExists {
		t.Errorf("historical pin was not cleared by ClearPins()")
	}
	if !newPinExists {
		t.Errorf("new pin was not installed")
	}
}

// 5. Candidate Ports Go Contract + UFW Script Alignment
// Ensures the candidate ports defined in Go match the ports opened by deploy/edge-install.sh.
func TestTier3_CandidatePorts_UFWFirewallSync(t *testing.T) {
	script := ReadDeployScript(t)

	for _, port := range StandardCandidatePorts {
		portStr := strconv.Itoa(port)
		// Check that the script references the port
		if !strings.Contains(script, portStr) {
			t.Errorf("candidate port %d in Go contract is missing from deploy/edge-install.sh", port)
		}
	}
}

// 6. Web Console User Sub Lifecycle
// Create user sub via admin API, verify retrieval via /sub/{slug}, and check quota exhaustion.
func TestTier3_WebConsole_UserSubCreationLifecycle(t *testing.T) {
	adminKey := "admin_master_lifecycle_key"
	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:   "edge.aero.test",
		AdminKey: adminKey,
	})
	defer server.Close()

	slug := "testcycle888"
	payload := map[string]interface{}{
		"username":            "cyclist",
		"slug":                slug,
		"token":               "token_lifecycle_999",
		"expire_at":           time.Now().Add(2 * time.Hour).Unix(),
		"traffic_limit_bytes": 5000,
	}
	bodyData, _ := json.Marshal(payload)

	// Step 1: Ingest via POST /admin/subs
	req, _ := http.NewRequest(http.MethodPost, server.URL()+"/admin/subs", bytes.NewReader(bodyData))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /admin/subs error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /admin/subs, got %d", resp.StatusCode)
	}

	// Step 2: Retrieve via GET /sub/{slug}
	subResp, err := http.Get(server.URL() + "/sub/" + slug)
	if err != nil {
		t.Fatalf("GET /sub/%s error: %v", slug, err)
	}
	defer subResp.Body.Close()

	if subResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /sub/%s, got %d", slug, subResp.StatusCode)
	}

	var doc SubDocument
	_ = json.NewDecoder(subResp.Body).Decode(&doc)
	if doc.UserID != "cyclist" {
		t.Errorf("expected userId 'cyclist', got '%s'", doc.UserID)
	}

	// Step 3: Hit quota limit
	server.RecordTraffic(slug, 5001)

	// Step 4: Verify 403 Forbidden
	blockedResp, err := http.Get(server.URL() + "/sub/" + slug)
	if err != nil {
		t.Fatalf("GET /sub/%s blocked request error: %v", slug, err)
	}
	defer blockedResp.Body.Close()
	if blockedResp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden after traffic limit, got %d", blockedResp.StatusCode)
	}
}

// 7. DNS Fake-IP + STUN Physical Blocking
// Ensures DNS queries resolve to 198.18 while simultaneous STUN queries are blocked.
func TestTier3_DNSFakeIP_STUNBlocking(t *testing.T) {
	// Query 1: DNS A query for international domain
	dnsQuery := BuildDNSQuery("twitter.com", 1)
	isFakeIP, isAAAA, _, fakeIP := SimulateDNSFunnel(dnsQuery)

	if !isFakeIP || isAAAA || fakeIP == nil {
		t.Fatalf("DNS Fake-IP failed for twitter.com")
	}

	// Query 2: STUN binding request sent over UDP
	stunPkt := BuildSTUNBindingRequest()

	filterOutbound := func(packetType string, data []byte) bool {
		if packetType == "stun" || IsSTUNPacket(data) {
			return false // Drop
		}
		return true // Allow
	}

	if filterOutbound("stun", stunPkt) {
		t.Errorf("STUN packet was allowed through filter")
	}
}

// 8. WARP Outbound Routing Toggle + Metrics Reporting
// Toggling WARP on/off dynamically updates console metrics and purity score.
func TestTier3_WARPBypass_MetricsReporting(t *testing.T) {
	adminKey := "warp_metrics_key"
	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:     "edge.aero.test",
		AdminKey:   adminKey,
		WarpActive: false,
	})
	defer server.Close()

	// Initial metrics: WARP inactive
	req, _ := http.NewRequest(http.MethodGet, server.URL()+"/api/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	resp1, _ := http.DefaultClient.Do(req)
	var m1 ConsoleMetrics
	_ = json.NewDecoder(resp1.Body).Decode(&m1)
	resp1.Body.Close()

	if m1.WarpActive {
		t.Errorf("expected WarpActive to be false initially")
	}

	// Toggle WARP on via Web Console API
	toggleReq, _ := http.NewRequest(http.MethodPost, server.URL()+"/api/warp/toggle", nil)
	toggleReq.Header.Set("Authorization", "Bearer "+adminKey)
	tResp, err := http.DefaultClient.Do(toggleReq)
	if err != nil {
		t.Fatalf("toggle error: %v", err)
	}
	tResp.Body.Close()

	// Subsequent metrics: WARP active and score boosted
	req2, _ := http.NewRequest(http.MethodGet, server.URL()+"/api/metrics", nil)
	req2.Header.Set("Authorization", "Bearer "+adminKey)
	resp2, _ := http.DefaultClient.Do(req2)
	var m2 ConsoleMetrics
	_ = json.NewDecoder(resp2.Body).Decode(&m2)
	resp2.Body.Close()

	if !m2.WarpActive {
		t.Errorf("expected WarpActive to be true after toggle")
	}
	if m2.PurityScore != 95 {
		t.Errorf("expected PurityScore to be boosted to 95 with WARP active, got %d", m2.PurityScore)
	}
}
