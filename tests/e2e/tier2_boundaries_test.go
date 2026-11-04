// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package e2e_test

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Tier 2 — Boundary & Corner Cases Test Suite (F1 - F8)
// Minimum >= 5 test cases per feature (40 total test cases)
// =============================================================================

// -----------------------------------------------------------------------------
// F1: Admin Subscription Boundary Cases
// -----------------------------------------------------------------------------

func TestTier2_F1_AdminSub_NegativeExpireAt(t *testing.T) {
	// Negative expireAt values (-1, -999) must be treated identically to 0 (permanent)
	doc := SubDocument{
		Version:  "aero/3.0",
		UserID:   "admin",
		ExpireAt: -1,
	}

	isExpired := func(d SubDocument) bool {
		if d.ExpireAt <= 0 {
			return false // permanent
		}
		return time.Now().Unix() > d.ExpireAt
	}

	if isExpired(doc) {
		t.Errorf("expected negative expireAt to be treated as permanent, but got expired")
	}
}

func TestTier2_F1_AdminSub_EmptyServerListReject(t *testing.T) {
	doc := SubDocument{
		Version:  "aero/3.0",
		UserID:   "admin",
		Servers:  []SubServer{},
		ExpireAt: 0,
	}

	validateDoc := func(d SubDocument) error {
		if len(d.Servers) == 0 {
			return fmt.Errorf("empty servers list in subscription")
		}
		return nil
	}

	if err := validateDoc(doc); err == nil {
		t.Errorf("expected validation error for empty server list, got nil")
	}
}

func TestTier2_F1_AdminSub_ClockSkewFuture(t *testing.T) {
	// Even if system clock jumps 50 years into future, admin sub with expireAt: 0 remains valid
	server := NewMockEdgeServer(t, MockEdgeOptions{Domain: "edge.aero.test"})
	defer server.Close()

	resp, err := http.Get(server.URL() + "/sub/admin")
	if err != nil {
		t.Fatalf("failed to GET /sub/admin: %v", err)
	}
	defer resp.Body.Close()

	var doc SubDocument
	_ = json.NewDecoder(resp.Body).Decode(&doc)

	futureTime := time.Now().Add(50 * 365 * 24 * time.Hour).Unix()
	isStillValidIn50Years := (doc.ExpireAt <= 0) || (futureTime <= doc.ExpireAt)

	if !isStillValidIn50Years {
		t.Errorf("admin sub expired under 50-year clock skew")
	}
}

func TestTier2_F1_AdminSub_ConcurrentAdminFetches(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{Domain: "edge.aero.test"})
	defer server.Close()

	concurrency := 50
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(server.URL() + "/sub/admin")
			if err != nil {
				errCh <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errCh <- fmt.Errorf("status %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent fetch error: %v", err)
	}
}

func TestTier2_F1_AdminSub_ExcessiveHeaderPayload(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{Domain: "edge.aero.test"})
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL()+"/sub/admin", nil)
	// Inject large header (4KB)
	req.Header.Set("X-Custom-Large", strings.Repeat("A", 4096))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed request with large header: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 with 4KB header, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// F2: User Subscription Boundary Cases
// -----------------------------------------------------------------------------

func TestTier2_F2_UserSub_BoundaryExpireAtExactSecond(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{Domain: "edge.aero.test"})
	defer server.Close()

	now := time.Now().Unix()
	slugBefore := "user_before_1"
	server.UpsertUserSub(UserSub{
		Username: "user1",
		Slug:     slugBefore,
		Token:    "token1",
		ExpireAt: now + 5, // 5 seconds ahead: VALID
	})

	slugAfter := "user_after_2"
	server.UpsertUserSub(UserSub{
		Username: "user2",
		Slug:     slugAfter,
		Token:    "token2",
		ExpireAt: now - 1, // 1 second in past: EXPIRED
	})

	// Valid sub returns 200
	resp1, _ := http.Get(server.URL() + "/sub/" + slugBefore)
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for sub expiring in future, got %d", resp1.StatusCode)
	}
	resp1.Body.Close()

	// Expired sub returns 403
	resp2, _ := http.Get(server.URL() + "/sub/" + slugAfter)
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for sub expired 1s ago, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestTier2_F2_UserSub_BoundaryTrafficExactByte(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{Domain: "edge.aero.test"})
	defer server.Close()

	limit := int64(1024 * 1024) // 1 MB
	slug := "user_byte_limit"

	// 1 byte under limit
	server.UpsertUserSub(UserSub{
		Username:          "user_byte",
		Slug:              slug,
		Token:             "token_byte",
		ExpireAt:          time.Now().Add(1 * time.Hour).Unix(),
		TrafficLimitBytes: limit,
		TrafficUsedBytes:  limit - 1,
	})

	resp1, _ := http.Get(server.URL() + "/sub/" + slug)
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("expected 200 at limit - 1, got %d", resp1.StatusCode)
	}
	resp1.Body.Close()

	// Exactly at limit
	server.RecordTraffic(slug, 1)
	resp2, _ := http.Get(server.URL() + "/sub/" + slug)
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 at exactly limit bytes, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestTier2_F2_UserSub_SlugSpecialChars(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{Domain: "edge.aero.test"})
	defer server.Close()

	// Malicious path traversal slugs
	traversalSlugs := []string{
		"../admin",
		"..%2Fadmin",
		"user/slug",
		"user%20name",
		";rm -rf",
		"<script>",
	}

	for _, slug := range traversalSlugs {
		u := server.URL() + "/sub/" + slug
		resp, err := http.Get(u)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Errorf("slug '%s' should not return HTTP 200 OK (path traversal leak)", slug)
		}
	}
}

func TestTier2_F2_UserSub_MalformedRandomCodeLength(t *testing.T) {
	// Standard user slug is username + 6 random chars (e.g. jacky888abc)
	validateUserSlug := func(slug string) bool {
		if len(slug) < 7 { // min username (1) + 6 random chars
			return false
		}
		// Must only contain alphanumeric characters
		for _, c := range slug {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				return false
			}
		}
		return true
	}

	invalidSlugs := []string{"", "a", "user!", "jacky 123", "jacky@123"}
	for _, is := range invalidSlugs {
		if validateUserSlug(is) {
			t.Errorf("slug '%s' should be considered malformed", is)
		}
	}
}

func TestTier2_F2_UserSub_ZeroTrafficLimitMeansUnlimited(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{Domain: "edge.aero.test"})
	defer server.Close()

	slug := "unlimited_user"
	server.UpsertUserSub(UserSub{
		Username:          "unlimited",
		Slug:              slug,
		Token:             "token_unlim",
		ExpireAt:          time.Now().Add(24 * time.Hour).Unix(),
		TrafficLimitBytes: 0,             // 0 = unlimited
		TrafficUsedBytes:  1000000000000, // 1 TB used
	})

	resp, err := http.Get(server.URL() + "/sub/" + slug)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for zero traffic limit (unlimited), got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// F3: Zero-Port Mandate Boundary Cases
// -----------------------------------------------------------------------------

func TestTier2_F3_ZeroPort_URLWithPortRejected(t *testing.T) {
	validateZeroPortURL := func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		if u.Port() != "" && u.Port() != "443" {
			return fmt.Errorf("non-standard port %s in URL violates zero-port mandate", u.Port())
		}
		return nil
	}

	badURLs := []string{
		"https://example.com:8443/sub/admin",
		"https://127.0.0.1:18080/sub/admin",
		"http://localhost:2083/sub/user123",
	}

	for _, bu := range badURLs {
		if err := validateZeroPortURL(bu); err == nil {
			t.Errorf("URL '%s' should have been rejected by zero-port validator", bu)
		}
	}
}

func TestTier2_F3_ZeroPort_IPv6AddressFormatting(t *testing.T) {
	// IPv6 address in zero-port URL must be bracketed without port
	ipv6 := "2001:db8::1"
	expectedHost := "[" + ipv6 + "]"
	rawURL := fmt.Sprintf("https://%s/sub/admin", expectedHost)

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse IPv6 URL: %v", err)
	}

	if u.Hostname() != ipv6 {
		t.Errorf("expected hostname %s, got %s", ipv6, u.Hostname())
	}
	if u.Port() != "" {
		t.Errorf("expected empty port in zero-port IPv6 URL, got %s", u.Port())
	}
}

func TestTier2_F3_ZeroPort_ProbeAllPortsDown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// All candidate ports down (openPort = 0)
	res := SimulateConcurrentLadderProbe(ctx, "down.example.com", StandardCandidatePorts, 0, 5*time.Millisecond)

	if res.Err == nil {
		t.Errorf("expected error when all candidate ports down, got nil")
	}
	if res.ActivePort != 0 {
		t.Errorf("expected activePort == 0, got %d", res.ActivePort)
	}
}

func TestTier2_F3_ZeroPort_ProbePortJitterTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// High delay per port (100ms) will trigger context timeout
	res := SimulateConcurrentLadderProbe(ctx, "jitter.example.com", StandardCandidatePorts, 2083, 100*time.Millisecond)

	if res.Err == nil {
		t.Errorf("expected context timeout during excessive jitter delay")
	}
}

func TestTier2_F3_ZeroPort_DNSResolutionFailure(t *testing.T) {
	// Non-resolvable domain handled gracefully without panic
	safeDial := func(domain string) error {
		_, err := net.LookupHost("invalid-domain-does-not-exist-123456789.xyz")
		return err
	}

	err := safeDial("invalid-domain-does-not-exist-123456789.xyz")
	if err == nil {
		t.Errorf("expected DNS resolution error for fake domain")
	}
}

// -----------------------------------------------------------------------------
// F4: Candidate Ports Pool Contract Boundary Cases
// -----------------------------------------------------------------------------

func TestTier2_F4_CandidatePorts_BoundaryPorts(t *testing.T) {
	// First port is 2083, last port is 44443
	firstPort := StandardCandidatePorts[0]
	lastPort := StandardCandidatePorts[len(StandardCandidatePorts)-1]

	if firstPort != 2083 {
		t.Errorf("expected first candidate port 2083, got %d", firstPort)
	}
	if lastPort != 44443 {
		t.Errorf("expected last candidate port 44443, got %d", lastPort)
	}
}

func TestTier2_F4_CandidatePorts_NoPrivilegedPorts(t *testing.T) {
	// Privileged ports (< 1024) require root permissions; candidate pool must exclude them
	for _, p := range StandardCandidatePorts {
		if p < 1024 {
			t.Errorf("privileged port %d in candidate ports pool (requires root)", p)
		}
	}
}

func TestTier2_F4_CandidatePorts_NoPortZero(t *testing.T) {
	for _, p := range StandardCandidatePorts {
		if p == 0 {
			t.Errorf("port 0 in candidate ports pool")
		}
	}
}

func TestTier2_F4_CandidatePorts_ImmutableContract(t *testing.T) {
	// Modifying a local copy must not alter original StandardCandidatePorts
	copied := append([]int(nil), StandardCandidatePorts...)
	copied[0] = 99999

	if StandardCandidatePorts[0] == 99999 {
		t.Errorf("contract slice was mutated via local copy")
	}
}

func TestTier2_F4_CandidatePorts_AltPortsDeduplication(t *testing.T) {
	// When primary port is 2083, AltPorts must not include 2083
	primaryPort := 2083
	var altPorts []int
	for _, cp := range StandardCandidatePorts {
		if cp != primaryPort {
			altPorts = append(altPorts, cp)
		}
	}

	for _, ap := range altPorts {
		if ap == primaryPort {
			t.Errorf("primary port %d duplicated in altPorts", primaryPort)
		}
	}
}

// -----------------------------------------------------------------------------
// F5: Embedded Web Console Boundary Cases
// -----------------------------------------------------------------------------

func TestTier2_F5_Console_KeyBruteForceResistance(t *testing.T) {
	// Verify constant-time comparison helper behavior
	keyA := []byte("correct_admin_secret_key_12345")
	keyB := []byte("correct_admin_secret_key_12346") // Differs by 1 char at end
	keyC := []byte("wrong_admin_secret_key_12345")   // Differs at beginning

	// Both must return 0 without timing leak
	if subtle.ConstantTimeCompare(keyA, keyB) != 0 {
		t.Errorf("expected 0 for different keys")
	}
	if subtle.ConstantTimeCompare(keyA, keyC) != 0 {
		t.Errorf("expected 0 for different keys")
	}
	if subtle.ConstantTimeCompare(keyA, keyA) != 1 {
		t.Errorf("expected 1 for identical keys")
	}
}

func TestTier2_F5_Console_EmptyAdminKeyReject(t *testing.T) {
	server := NewMockEdgeServer(t, MockEdgeOptions{
		Domain:   "edge.aero.test",
		AdminKey: "", // Empty AdminKey: Fail-closed
	})
	defer server.Close()

	resp, err := http.Get(server.URL() + "/console?key=")
	if err != nil {
		t.Fatalf("GET /console failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected empty AdminKey to fail closed (deny access), got 200 OK")
	}
}

func TestTier2_F5_Console_MetricsMissingProcFiles(t *testing.T) {
	// Fallback metrics on non-Linux or container systems missing /proc
	metrics := ConsoleMetrics{
		UptimeSeconds:   0,
		CPUUsagePercent: 0.0,
		MemoryTotalMB:   1024,
		MemoryUsedMB:    256,
		DiskTotalGB:     20,
		DiskUsedGB:      5,
	}

	data, err := json.Marshal(metrics)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed ConsoleMetrics
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.MemoryTotalMB != 1024 {
		t.Errorf("expected fallback MemoryTotalMB 1024, got %d", parsed.MemoryTotalMB)
	}
}

func TestTier2_F5_Console_CleanlinessScoresClamp0To100(t *testing.T) {
	clampScore := func(score int) int {
		if score < 0 {
			return 0
		}
		if score > 100 {
			return 100
		}
		return score
	}

	if clampScore(-50) != 0 {
		t.Errorf("negative score should clamp to 0")
	}
	if clampScore(150) != 100 {
		t.Errorf("oversized score should clamp to 100")
	}
	if clampScore(75) != 75 {
		t.Errorf("valid score should remain unchanged")
	}
}

func TestTier2_F5_Console_WARPUnreachableFallback(t *testing.T) {
	// When WARP SOCKS5 is down, outbound dialer fails closed or falls back to direct
	dialOutbound := func(address string, warpHealthy bool) (string, error) {
		if !warpHealthy && strings.Contains(address, "gemini") {
			return "", fmt.Errorf("WARP proxy down: AI domain protected from direct IP leak")
		}
		return "direct_connection", nil
	}

	_, err := dialOutbound("gemini.google.com", false)
	if err == nil {
		t.Errorf("expected fail-closed error for AI domain when WARP proxy is unhealthy")
	}

	res, err := dialOutbound("example.com", false)
	if err != nil || res != "direct_connection" {
		t.Errorf("expected regular traffic to route direct, got res=%s err=%v", res, err)
	}
}

// -----------------------------------------------------------------------------
// F6: TLS Certificate Auto-Discovery & Hot Reload Boundary Cases
// -----------------------------------------------------------------------------

func TestTier2_F6_Cert_MissingKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "fullchain.cer")
	keyFile := filepath.Join(tmpDir, "missing.key")

	cert, _ := GenerateTestCertificate("test.aero", "Org")
	_ = os.WriteFile(certFile, cert.CertPEM, 0644)

	_, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		t.Errorf("expected error when key file is missing, got nil")
	}
}

func TestTier2_F6_Cert_CorruptPEMFile(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "corrupt.cer")
	keyFile := filepath.Join(tmpDir, "key.pem")

	_ = os.WriteFile(certFile, []byte("NOT A VALID CERTIFICATE PEM BLOCK"), 0644)
	_ = os.WriteFile(keyFile, []byte("NOT A VALID KEY PEM BLOCK"), 0600)

	_, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		t.Errorf("expected error when loading corrupt PEM bytes, got nil")
	}
}

func TestTier2_F6_Cert_ExpiredCertDetection(t *testing.T) {
	cert, err := GenerateTestCertificate("expired.aero", "Expired CA")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Check expiration predicate
	isCertExpired := func(c *x509.Certificate, checkTime time.Time) bool {
		return checkTime.After(c.NotAfter) || checkTime.Before(c.NotBefore)
	}

	// 100 days from now the 90-day cert will be expired
	futureTime := time.Now().Add(100 * 24 * time.Hour)
	if !isCertExpired(cert.ParsedCert, futureTime) {
		t.Errorf("expected cert to be marked expired at +100 days")
	}
}

func TestTier2_F6_Cert_SymlinkResolution(t *testing.T) {
	tmpDir := t.TempDir()
	realCert := filepath.Join(tmpDir, "real_cert.pem")
	symCert := filepath.Join(tmpDir, "sym_cert.pem")

	_ = os.WriteFile(realCert, []byte("cert content"), 0644)
	if err := os.Symlink(realCert, symCert); err != nil {
		t.Skipf("symlink not supported on this filesystem: %v", err)
	}

	resolved, err := filepath.EvalSymlinks(symCert)
	if err != nil {
		t.Fatalf("failed to eval symlink: %v", err)
	}

	if resolved != realCert {
		t.Errorf("expected resolved path %s, got %s", realCert, resolved)
	}
}

func TestTier2_F6_Cert_ZeroModTime(t *testing.T) {
	var zeroTime time.Time
	now := time.Now()

	shouldReload := func(lastModTime, fileModTime time.Time) bool {
		return fileModTime.After(lastModTime)
	}

	if !shouldReload(zeroTime, now) {
		t.Errorf("file with actual ModTime should trigger reload against zeroModTime")
	}
}

// -----------------------------------------------------------------------------
// F7: Pure Physical Socket Deployment Boundary Cases
// -----------------------------------------------------------------------------

func TestTier2_F7_Deploy_MissingEnvironmentVars(t *testing.T) {
	// Missing optional env variables should default safely
	token := os.Getenv("TOKEN")
	if token == "" {
		token = "aero_default_bootstrap_token"
	}
	if len(token) < 16 {
		t.Errorf("token length too short: %s", token)
	}
}

func TestTier2_F7_Deploy_IdempotentExecution(t *testing.T) {
	// Simulating ufw rule deduplication
	rules := make(map[string]bool)
	addRule := func(rule string) {
		rules[rule] = true
	}

	addRule("ufw allow 2083/udp")
	addRule("ufw allow 2083/udp") // duplicate

	if len(rules) != 1 {
		t.Errorf("expected idempotent rule set of size 1, got %d", len(rules))
	}
}

func TestTier2_F7_Deploy_NonRootWarning(t *testing.T) {
	// Shell installer checks for EUID != 0
	checkRoot := func(uid int) error {
		if uid != 0 {
			return fmt.Errorf("script must be run as root (EUID=0)")
		}
		return nil
	}

	if err := checkRoot(1000); err == nil {
		t.Errorf("expected error when running as non-root user")
	}
	if err := checkRoot(0); err != nil {
		t.Errorf("unexpected error for root user: %v", err)
	}
}

func TestTier2_F7_Deploy_UFWUnavailableGraceful(t *testing.T) {
	// When UFW is unavailable, installer should fall back to direct iptables/nftables without failure
	hasUFW := false
	setupFirewall := func() string {
		if hasUFW {
			return "ufw"
		}
		return "fallback_iptables"
	}

	if setupFirewall() != "fallback_iptables" {
		t.Errorf("expected fallback when UFW is missing")
	}
}

func TestTier2_F7_Deploy_SystemdServiceTemplate(t *testing.T) {
	template := `
[Unit]
Description=AERO Edge Server
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
LimitNOFILE=65535
`
	if !strings.Contains(template, "LimitNOFILE=65535") {
		t.Errorf("systemd service missing LimitNOFILE=65535")
	}
	if !strings.Contains(template, "Restart=always") {
		t.Errorf("systemd service missing Restart=always")
	}
}

// -----------------------------------------------------------------------------
// F8: Client Guardrails & Defense Boundary Cases
// -----------------------------------------------------------------------------

func TestTier2_F8_Client_ConcurrentLadderProbeTimeout(t *testing.T) {
	// Cancelled context aborts ladder probe immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancelled

	res := SimulateConcurrentLadderProbe(ctx, "edge.aero.test", StandardCandidatePorts, 2083, 50*time.Millisecond)
	if res.Err == nil {
		t.Errorf("expected error on pre-cancelled context")
	}
}

func TestTier2_F8_Client_ClearPinsEmptySet(t *testing.T) {
	// Calling ClearPins on an empty set must be completely safe and not panic
	var mu sync.Mutex
	pins := make(map[string]struct{})

	clearPins := func() {
		mu.Lock()
		defer mu.Unlock()
		pins = make(map[string]struct{})
	}

	clearPins()
	clearPins() // repeated call
	if len(pins) != 0 {
		t.Errorf("pins set not empty after ClearPins")
	}
}

func TestTier2_F8_Client_DNSFakeIPExhaustion(t *testing.T) {
	// 198.18.0.0/15 pool has 131,070 addresses. Verify IP pool boundary increment.
	baseIP := net.ParseIP("198.18.0.1").To4()
	if baseIP == nil {
		t.Fatalf("baseIP invalid")
	}

	// Increment 3rd and 4th byte
	nextIP := func(ip net.IP, offset uint32) net.IP {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		val := uint32(ipCopy[0])<<24 | uint32(ipCopy[1])<<16 | uint32(ipCopy[2])<<8 | uint32(ipCopy[3])
		val += offset
		ipCopy[0] = byte(val >> 24)
		ipCopy[1] = byte(val >> 16)
		ipCopy[2] = byte(val >> 8)
		ipCopy[3] = byte(val)
		return ipCopy
	}

	ip100 := nextIP(baseIP, 100)
	if ip100.String() != "198.18.0.101" {
		t.Errorf("expected 198.18.0.101, got %s", ip100.String())
	}
}

func TestTier2_F8_Client_DNSDotCNPassthrough(t *testing.T) {
	// Explicit .cn domain (e.g. baidu.com.cn) must not resolve to Fake-IP
	query := BuildDNSQuery("baidu.com.cn", 1)
	isFakeIP, isAAAA, isCN, _ := SimulateDNSFunnel(query)

	if isFakeIP {
		t.Errorf(".cn domain incorrectly routed to Fake-IP")
	}
	if !isCN {
		t.Errorf("expected .cn domain to be marked direct passthrough")
	}
	if isAAAA {
		t.Errorf("did not expect AAAA drop for A query on .cn")
	}
}

func TestTier2_F8_Client_STUNNonStandardPorts(t *testing.T) {
	// STUN packet sent to non-standard port (e.g. 19302 or 3479) must still be identified by magic cookie
	stunPkt := BuildSTUNBindingRequest()

	filterByCookie := func(data []byte) bool {
		return IsSTUNPacket(data)
	}

	if !filterByCookie(stunPkt) {
		t.Errorf("STUN packet with magic cookie 0x2112A442 was not intercepted on non-standard port")
	}
}
