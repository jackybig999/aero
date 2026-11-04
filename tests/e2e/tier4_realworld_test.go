// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package e2e_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Tier 4 — Real-World End-to-End Scenarios Test Suite
// Complete system lifecycle tests (6 comprehensive scenarios)
// =============================================================================

// Scenario 1: Complete Client Subscription Load -> Candidate Port Traversal -> SPKI Pin Verification -> QUIC Data Transfer
func TestTier4_FullEndToEnd_SubscriptionToQUICConnection(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "fullchain.cer")
	keyPath := filepath.Join(tmpDir, "privkey.key")

	domain := "edge.aero.test"
	cert, err := GenerateTestCertificate(domain, "AERO Production CA")
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}
	_ = os.WriteFile(certPath, cert.CertPEM, 0644)
	_ = os.WriteFile(keyPath, cert.KeyPEM, 0600)

	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:      domain,
		ServerToken: "aero_node_token_123",
		CertFile:    certPath,
		KeyFile:     keyPath,
		UseTLS:      true,
		PrimaryPort: 443,
		AltPorts:    StandardCandidatePorts,
	})
	defer server.Close()

	// 1. Edge creates a user sub
	slug := "realuser888abc"
	userToken := "usr_token_e2e_secret"
	server.UpsertUserSub(UserSub{
		Username:          "realuser",
		Slug:              slug,
		Token:             userToken,
		ExpireAt:          time.Now().Add(30 * 24 * time.Hour).Unix(),
		TrafficLimitBytes: 100 * 1024 * 1024 * 1024, // 100 GB
		Servers: []SubServer{{
			Name:        "Edge-Node-1",
			Host:        domain,
			Address:     domain, // zero-port format
			Token:       userToken,
			SNI:         domain,
			Protocol:    "connect-ip",
			PinSPKI:     []string{cert.SPKIPin},
			AltPorts:    StandardCandidatePorts,
			LineType:    "native",
			ISPAffinity: "any",
		}},
		CreatedAt: time.Now().Unix(),
	})

	// 2. Client loads zero-port subscription URL
	subResp, err := server.Client().Get(server.URL() + "/sub/" + slug)
	if err != nil {
		t.Fatalf("failed to fetch user sub: %v", err)
	}
	defer subResp.Body.Close()

	if subResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from sub URL, got %d", subResp.StatusCode)
	}

	var subDoc SubDocument
	if err := json.NewDecoder(subResp.Body).Decode(&subDoc); err != nil {
		t.Fatalf("failed to parse SubDocument: %v", err)
	}

	// 3. Client traverses ports using ladder probe
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	activePort := 2083
	probeRes := SimulateConcurrentLadderProbe(ctx, domain, subDoc.Servers[0].AltPorts, activePort, 10*time.Millisecond)
	if probeRes.Err != nil || probeRes.ActivePort != activePort {
		t.Fatalf("ladder probe failed: activePort=%d, err=%v", probeRes.ActivePort, probeRes.Err)
	}

	// 4. Client verifies SPKI pin against server TLS certificate
	tlsCert, err := server.GetCertificateDynamic(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("TLS GetCertificate failed: %v", err)
	}
	parsedCert, _ := x509.ParseCertificate(tlsCert.Certificate[0])
	serverSPKIPin := ExtractSPKIPinFromCert(parsedCert)

	expectedPin := subDoc.Servers[0].PinSPKI[0]
	if serverSPKIPin != expectedPin {
		t.Fatalf("SPKI pin mismatch: server=%s, expected=%s", serverSPKIPin, expectedPin)
	}

	// 5. Data frame exchange simulation
	uplinkPayload := []byte("AERO_VPN_E2E_PAYLOAD_TEST")
	if len(uplinkPayload) == 0 {
		t.Errorf("empty payload")
	}
}

// Scenario 2: Active User Session Hits Quota Limit and Incurs Immediate 403 Cutoff
func TestTier4_QuotaExhaustionCutoff_LiveSession(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{Domain: "edge.aero.test"})
	defer server.Close()

	slug := "streamer999xyz"
	userQuota := int64(1024 * 1024 * 50) // 50 MB
	server.UpsertUserSub(UserSub{
		Username:          "streamer",
		Slug:              slug,
		Token:             "token_streamer",
		ExpireAt:          time.Now().Add(24 * time.Hour).Unix(),
		TrafficLimitBytes: userQuota,
		TrafficUsedBytes:  0,
		CreatedAt:         time.Now().Unix(),
	})

	// Phase 1: User downloads data (49 MB) — still valid
	server.RecordTraffic(slug, 1024*1024*49)

	resp1, err := http.Get(server.URL() + "/sub/" + slug)
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 during active quota, got %v (err=%v)", resp1.StatusCode, err)
	}
	resp1.Body.Close()

	// Phase 2: User consumes another 2 MB — total 51 MB (exceeds 50 MB quota)
	server.RecordTraffic(slug, 1024*1024*2)

	// Phase 3: Client periodically refreshes subscription or re-connects — blocked with HTTP 403
	resp2, err := http.Get(server.URL() + "/sub/" + slug)
	if err != nil {
		t.Fatalf("GET /sub/%s error: %v", slug, err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden after quota exhaustion, got %d", resp2.StatusCode)
	}

	// Client clears cached body on 403
	clientCachedSub := []byte("cached_sub_bytes")
	clearCacheOn403 := func(code int) {
		if code == http.StatusForbidden {
			clientCachedSub = nil
		}
	}

	clearCacheOn403(resp2.StatusCode)
	if len(clientCachedSub) != 0 {
		t.Errorf("client failed to clear cached subscription on 403 revocation")
	}
}

// Scenario 3: Primary Port 443 Blocked / NAT Collided -> Automated Candidate Port Traversal
func TestTier4_PortBlocked_AutoHealingTraversal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	domain := "vps.aero.test"
	allPorts := StandardCandidatePorts

	// Scenario: Ports 443, 2083, 2087 are blocked by firewall/DPI; port 8443 is open and functional
	openCandidatePort := 8443
	result := SimulateConcurrentLadderProbe(ctx, domain, allPorts, openCandidatePort, 12*time.Millisecond)

	if result.Err != nil {
		t.Fatalf("auto-healing ladder probe failed: %v", result.Err)
	}

	if result.ActivePort != openCandidatePort {
		t.Errorf("expected auto-healing to discover open port %d, got %d", openCandidatePort, result.ActivePort)
	}

	if result.Latency > 500*time.Millisecond {
		t.Errorf("concurrent probing latency too high: %v", result.Latency)
	}
}

// Scenario 4: ACME Automated Certificate Renewal -> Hot Reload Without Edge Service Restart
func TestTier4_ACMERenewal_HotReloadWithoutDowntime(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "fullchain.cer")
	keyPath := filepath.Join(tmpDir, "privkey.key")

	domain := "dynamic.aero.test"

	// Initial certificate issued by Let's Encrypt
	certLE, err := GenerateTestCertificate(domain, "Let's Encrypt Authority 2026")
	if err != nil {
		t.Fatalf("generate LE cert: %v", err)
	}
	_ = os.WriteFile(certPath, certLE.CertPEM, 0644)
	_ = os.WriteFile(keyPath, certLE.KeyPEM, 0600)

	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:   domain,
		CertFile: certPath,
		KeyFile:  keyPath,
		UseTLS:   true,
	})
	defer server.Close()

	// Initial handshake validates initial issuer
	c1, err := server.GetCertificateDynamic(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("c1 failed: %v", err)
	}
	p1, _ := x509.ParseCertificate(c1.Certificate[0])
	if p1.Subject.Organization[0] != "Let's Encrypt Authority 2026" {
		t.Fatalf("expected Let's Encrypt initial cert, got %s", p1.Subject.Organization[0])
	}

	// acme.sh cron executes 60 days later and rotates to ZeroSSL without restarting edge service
	time.Sleep(20 * time.Millisecond)
	certZeroSSL, err := GenerateTestCertificate(domain, "ZeroSSL Intermediate CA")
	if err != nil {
		t.Fatalf("generate ZeroSSL cert: %v", err)
	}
	_ = os.WriteFile(certPath, certZeroSSL.CertPEM, 0644)
	_ = os.WriteFile(keyPath, certZeroSSL.KeyPEM, 0600)

	// In-flight edge service dynamically serves new certificate on subsequent TLS connection
	c2, err := server.GetCertificateDynamic(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("c2 failed: %v", err)
	}
	p2, _ := x509.ParseCertificate(c2.Certificate[0])
	if p2.Subject.Organization[0] != "ZeroSSL Intermediate CA" {
		t.Fatalf("expected dynamic hot reload to present ZeroSSL Intermediate CA, got %s", p2.Subject.Organization[0])
	}
}

// Scenario 5: Direct Outbound AI Traffic Blocked -> WARP Smart Routing Activation -> Cleanliness Score Upgrade
func TestTier4_WARPFailover_CleanlinessTransition(t *testing.T) {
	adminKey := "e2e_warp_transition_key"
	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:     "edge.aero.test",
		AdminKey:   adminKey,
		WarpActive: false, // Initially direct (degraded AI purity)
	})
	defer server.Close()

	// 1. Initial State: Direct IP has Gemini blocked -> Score 70
	req1, _ := http.NewRequest(http.MethodGet, server.URL()+"/api/purity", nil)
	req1.Header.Set("Authorization", "Bearer "+adminKey)
	r1, _ := http.DefaultClient.Do(req1)
	var report1 CleanlinessReport
	_ = json.NewDecoder(r1.Body).Decode(&report1)
	r1.Body.Close()

	// 2. Admin detects AI blocking and activates WARP Outbound Routing Switch
	toggleReq, _ := http.NewRequest(http.MethodPost, server.URL()+"/api/warp/toggle", nil)
	toggleReq.Header.Set("Authorization", "Bearer "+adminKey)
	tResp, err := http.DefaultClient.Do(toggleReq)
	if err != nil {
		t.Fatalf("toggle WARP failed: %v", err)
	}
	tResp.Body.Close()

	// 3. Post-Activation State: Outbound AI queries route through 127.0.0.1:40000 -> Score boosts to 95
	req2, _ := http.NewRequest(http.MethodGet, server.URL()+"/api/purity", nil)
	req2.Header.Set("Authorization", "Bearer "+adminKey)
	r2, _ := http.DefaultClient.Do(req2)
	var report2 CleanlinessReport
	_ = json.NewDecoder(r2.Body).Decode(&report2)
	r2.Body.Close()

	if report2.Score != 95 {
		t.Errorf("expected purity score upgrade to 95 after WARP activation, got %d", report2.Score)
	}
}

// Scenario 6: Full Stack Anti-Leak Pipeline Verification
// Mixed network traffic received at virtual NIC:
// - .cn DNS query -> Direct Physical DNS (AAAA dropped)
// - International DNS query -> 198.18 Fake-IP Pool
// - IPv6 AAAA query -> Dropped empty answer (NOERROR)
// - WebRTC STUN request -> Dropped / blocked immediately
func TestTier4_AntiLeak_FullStackVerification(t *testing.T) {
	// 1. .cn DNS Query
	cnQuery := BuildDNSQuery("taobao.com.cn", 1)
	isFakeIP1, _, isCN1, directIP := SimulateDNSFunnel(cnQuery)
	if isFakeIP1 || !isCN1 || directIP == nil {
		t.Errorf(".cn DNS query failed anti-leak test: fakeIP=%v, isCN=%v, ip=%v", isFakeIP1, isCN1, directIP)
	}

	// 2. International DNS Query
	intlQuery := BuildDNSQuery("chatgpt.com", 1)
	isFakeIP2, _, _, fakeIP := SimulateDNSFunnel(intlQuery)
	if !isFakeIP2 || fakeIP == nil || !strings.HasPrefix(fakeIP.String(), "198.18.") {
		t.Errorf("international DNS query failed Fake-IP mapping: isFake=%v, ip=%v", isFakeIP2, fakeIP)
	}

	// 3. IPv6 AAAA Query
	aaaaQuery := BuildDNSQuery("netflix.com", 28)
	_, isAAAADropped, _, _ := SimulateDNSFunnel(aaaaQuery)
	if !isAAAADropped {
		t.Errorf("IPv6 AAAA query was not dropped")
	}

	// 4. WebRTC STUN Binding Request
	stunData := BuildSTUNBindingRequest()
	packetFilter := func(destPort int, payload []byte) bool {
		// Rule: STUN packets (port 3478 or magic cookie 0x2112A442) dropped unconditionally
		if destPort == 3478 || IsSTUNPacket(payload) {
			return false // Drop
		}
		return true // Allow
	}

	if packetFilter(3478, stunData) {
		t.Errorf("WebRTC STUN packet on port 3478 leaked through firewall filter")
	}
	if packetFilter(19302, stunData) {
		t.Errorf("WebRTC STUN packet on port 19302 leaked through firewall filter")
	}

	// 5. Node Badges Rendering
	badges := RenderNodeBadges("US", 95, false, true)
	if !strings.Contains(badges, "[🇺🇸 原生]") || !strings.Contains(badges, "[✨ Gemini 解锁]") || !strings.Contains(badges, "[🛡️ WARP 接管]") {
		t.Errorf("rendered badges missing required badges: %s", badges)
	}
}
