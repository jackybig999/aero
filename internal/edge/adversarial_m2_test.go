// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAdversarial_DynamicTLS_ConcurrentHotReload stress-tests DynamicCertLoader
// under high concurrency (128 goroutines) while files are repeatedly updated on disk.
func TestAdversarial_DynamicTLS_ConcurrentHotReload(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "fullchain.cer")
	keyFile := filepath.Join(tmpDir, "privkey.key")

	// Generation 0 initial cert
	certPEM0, keyPEM0 := generateTestCertPEMForEdge(t, "edge.aero.test", "Gen 0 Initial")
	if err := os.WriteFile(certFile, certPEM0, 0644); err != nil {
		t.Fatalf("write cert0: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM0, 0600); err != nil {
		t.Fatalf("write key0: %v", err)
	}

	initialPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("initial LoadX509KeyPair: %v", err)
	}

	loader := NewDynamicCertLoader(certFile, keyFile, &initialPair)

	const workerCount = 128
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(workerCount)

	stopWriters := make(chan struct{})
	var writeErrors atomic.Int64
	var readErrors atomic.Int64
	var invalidCerts atomic.Int64

	// Background writer goroutine rapidly swapping certs between generations
	go func() {
		defer close(stopWriters)
		for gen := 1; gen <= 5; gen++ {
			time.Sleep(30 * time.Millisecond)
			orgName := fmt.Sprintf("Gen %d Active", gen)
			cPEM, kPEM := generateTestCertPEMForEdge(t, "edge.aero.test", orgName)
			if err := os.WriteFile(keyFile, kPEM, 0600); err != nil {
				writeErrors.Add(1)
			}
			if err := os.WriteFile(certFile, cPEM, 0644); err != nil {
				writeErrors.Add(1)
			}
		}
	}()

	// 128 Concurrent reader workers hitting GetCertificate
	for i := 0; i < workerCount; i++ {
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < iterations; iter++ {
				c, gerr := loader.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.aero.test"})
				if gerr != nil || c == nil || len(c.Certificate) == 0 {
					readErrors.Add(1)
					continue
				}
				p, perr := x509.ParseCertificate(c.Certificate[0])
				if perr != nil || len(p.Subject.Organization) == 0 {
					invalidCerts.Add(1)
					continue
				}
				org := p.Subject.Organization[0]
				if !strings.HasPrefix(org, "Gen ") {
					invalidCerts.Add(1)
				}
				time.Sleep(100 * time.Microsecond)
			}
		}(i)
	}

	wg.Wait()
	<-stopWriters

	if writeErrors.Load() > 0 {
		t.Fatalf("detected %d disk write errors during test", writeErrors.Load())
	}
	if readErrors.Load() > 0 {
		t.Fatalf("detected %d GetCertificate errors under concurrent hot reload", readErrors.Load())
	}
	if invalidCerts.Load() > 0 {
		t.Fatalf("detected %d invalid/half-initialized certificates under concurrency", invalidCerts.Load())
	}

	// Final verification: after all updates complete, must return final generation
	finalCert, err := loader.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.aero.test"})
	if err != nil {
		t.Fatalf("final GetCertificate: %v", err)
	}
	finalParsed, _ := x509.ParseCertificate(finalCert.Certificate[0])
	if finalParsed.Subject.Organization[0] != "Gen 5 Active" {
		t.Fatalf("expected final certificate 'Gen 5 Active', got %q", finalParsed.Subject.Organization[0])
	}
}

// TestAdversarial_DynamicTLS_CorruptionResilience verifies that corrupted,
// truncated, deleted, or mismatched files do NOT crash the server and gracefully fall back to cached cert.
func TestAdversarial_DynamicTLS_CorruptionResilience(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "fullchain.cer")
	keyFile := filepath.Join(tmpDir, "privkey.key")

	certPEM, keyPEM := generateTestCertPEMForEdge(t, "edge.aero.test", "Valid Fallback Cert")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("initial pair: %v", err)
	}
	loader := NewDynamicCertLoader(certFile, keyFile, &pair)

	// Verify initial valid cert
	c0, err := loader.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.aero.test"})
	if err != nil {
		t.Fatalf("c0: %v", err)
	}
	p0, _ := x509.ParseCertificate(c0.Certificate[0])
	if p0.Subject.Organization[0] != "Valid Fallback Cert" {
		t.Fatalf("unexpected initial cert: %s", p0.Subject.Organization[0])
	}

	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	stopHammering := make(chan struct{})
	var failCount atomic.Int64

	// Start 64 hammer goroutines
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopHammering:
					return
				default:
					c, err := loader.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.aero.test"})
					if err != nil || c == nil {
						failCount.Add(1)
						continue
					}
					p, _ := x509.ParseCertificate(c.Certificate[0])
					if !strings.HasPrefix(p.Subject.Organization[0], "Valid ") {
						failCount.Add(1)
					}
					time.Sleep(50 * time.Microsecond)
				}
			}
		}()
	}

	// Corruption scenario 1: Truncated cert file (incomplete write)
	time.Sleep(20 * time.Millisecond)
	_ = os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nINCOMPLETE_GARBAGE"), 0644)
	time.Sleep(20 * time.Millisecond)

	// Corruption scenario 2: 0-byte cert file
	_ = os.WriteFile(certFile, []byte{}, 0644)
	time.Sleep(20 * time.Millisecond)

	// Corruption scenario 3: Key updated to a new key, but cert left mismatched
	_, mismatchedKey := generateTestCertPEMForEdge(t, "edge.aero.test", "Mismatched Key")
	_ = os.WriteFile(keyFile, mismatchedKey, 0600)
	_ = os.WriteFile(certFile, certPEM, 0644) // touch cert to trigger modTime reload
	time.Sleep(20 * time.Millisecond)

	// Corruption scenario 4: Cert file deleted
	_ = os.Remove(certFile)
	time.Sleep(20 * time.Millisecond)

	// Corruption scenario 5: Corrupted key file
	_ = os.WriteFile(certFile, certPEM, 0644)
	_ = os.WriteFile(keyFile, []byte("BAD PRIVATE KEY DATA"), 0600)
	time.Sleep(20 * time.Millisecond)

	// Stop hammering and verify zero client errors occurred
	close(stopHammering)
	wg.Wait()

	if failCount.Load() > 0 {
		t.Fatalf("detected %d failures during corruption hammer; graceful fallback violated", failCount.Load())
	}

	// Recovery Phase: write valid new cert & key
	time.Sleep(20 * time.Millisecond)
	recoveredCertPEM, recoveredKeyPEM := generateTestCertPEMForEdge(t, "edge.aero.test", "Valid Recovered Cert")
	if err := os.WriteFile(keyFile, recoveredKeyPEM, 0600); err != nil {
		t.Fatalf("write recovered key: %v", err)
	}
	if err := os.WriteFile(certFile, recoveredCertPEM, 0644); err != nil {
		t.Fatalf("write recovered cert: %v", err)
	}

	// Must cleanly recover and present new cert
	cRec, err := loader.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.aero.test"})
	if err != nil {
		t.Fatalf("expected recovery after corruption, got error: %v", err)
	}
	pRec, _ := x509.ParseCertificate(cRec.Certificate[0])
	if pRec.Subject.Organization[0] != "Valid Recovered Cert" {
		t.Fatalf("expected 'Valid Recovered Cert', got %q", pRec.Subject.Organization[0])
	}
}

// TestAdversarial_ACME_AutoDiscovery_Boundaries tests discovery edge cases:
// non-existent dirs, file-as-dir, 0000 unreadable dirs, 0-byte files, and domain variations.
func TestAdversarial_ACME_AutoDiscovery_Boundaries(t *testing.T) {
	// 1. Non-existent base directory
	_, _, found := DiscoverACMECertIn([]string{"/nonexistent/directory/test/12345"}, "node.aero.test")
	if found {
		t.Fatal("expected found=false for non-existent base directory")
	}

	// 2. Empty base dirs and domains
	_, _, found = DiscoverACMECertIn(nil)
	if found {
		t.Fatal("expected found=false for nil baseDirs")
	}
	_, _, found = DiscoverACMECertIn([]string{""}, "")
	if found {
		t.Fatal("expected found=false for empty inputs")
	}

	// 3. File instead of directory
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "not_a_dir")
	_ = os.WriteFile(filePath, []byte("regular file"), 0644)
	_, _, found = DiscoverACMECertIn([]string{filePath}, "node.aero.test")
	if found {
		t.Fatal("expected found=false when base dir is a regular file")
	}

	// 4. Zero-byte cert and key handling
	domain := "boundary.aero.test"
	acmeBase := filepath.Join(tmpDir, ".acme.sh")
	eccDir := filepath.Join(acmeBase, domain+"_ecc")
	_ = os.MkdirAll(eccDir, 0755)

	emptyCert := filepath.Join(eccDir, "fullchain.cer")
	_ = os.WriteFile(emptyCert, []byte{}, 0644)
	emptyKey := filepath.Join(eccDir, domain+".key")
	_ = os.WriteFile(emptyKey, []byte{}, 0600)

	_, _, found = DiscoverACMECertIn([]string{acmeBase}, domain)
	if found {
		t.Fatal("expected found=false for 0-byte cert and key files")
	}

	// 5. Only cert exists, key missing
	certPEM, keyPEM := generateTestCertPEMForEdge(t, domain, "ACME Boundary CA")
	_ = os.WriteFile(emptyCert, certPEM, 0644)
	_ = os.Remove(emptyKey)
	_, _, found = DiscoverACMECertIn([]string{acmeBase}, domain)
	if found {
		t.Fatal("expected found=false when key is missing")
	}

	// 6. Only key exists, cert missing
	_ = os.Remove(emptyCert)
	_ = os.WriteFile(emptyKey, keyPEM, 0600)
	_, _, found = DiscoverACMECertIn([]string{acmeBase}, domain)
	if found {
		t.Fatal("expected found=false when cert is missing")
	}

	// 7. Both valid: discovery succeeds
	_ = os.WriteFile(emptyCert, certPEM, 0644)
	foundC, foundK, found := DiscoverACMECertIn([]string{acmeBase}, domain)
	if !found || foundC != emptyCert || foundK != emptyKey {
		t.Fatalf("expected successful discovery of valid cert and key, got (%s, %s, %v)", foundC, foundK, found)
	}

	// 8. Port stripping and formatting variations
	portDomains := []string{
		domain + ":443",
		domain + ":2083",
		"[" + domain + "]",
		"  " + domain + "  ",
	}
	for _, pd := range portDomains {
		fc, fk, ok := DiscoverACMECertIn([]string{acmeBase}, pd)
		if !ok || fc != emptyCert || fk != emptyKey {
			t.Errorf("failed to discover cert for domain variation %q", pd)
		}
	}

	// 9. Loopback and IP filtering: must never attempt ACME discovery for IPs or localhost
	ipHosts := []string{"127.0.0.1", "::1", "localhost", "10.0.0.1", "1.1.1.1"}
	for _, ipHost := range ipHosts {
		_, _, ok := DiscoverACMECertIn([]string{acmeBase}, ipHost)
		if ok {
			t.Errorf("ACME discovery should ignore IP/localhost host %q", ipHost)
		}
	}

	// 10. Priority: ECC (_ecc) over RSA (non-ecc)
	rsaDir := filepath.Join(acmeBase, domain)
	_ = os.MkdirAll(rsaDir, 0755)
	rsaCert := filepath.Join(rsaDir, "fullchain.cer")
	rsaKey := filepath.Join(rsaDir, domain+".key")
	rsaCertPEM, rsaKeyPEM := generateTestCertPEMForEdge(t, domain, "RSA CA")
	_ = os.WriteFile(rsaCert, rsaCertPEM, 0644)
	_ = os.WriteFile(rsaKey, rsaKeyPEM, 0600)

	fcPriority, _, ok := DiscoverACMECertIn([]string{acmeBase}, domain)
	if !ok || fcPriority != emptyCert {
		t.Fatalf("expected ECC cert %s to take priority over RSA cert %s, got %s", emptyCert, rsaCert, fcPriority)
	}

	// 11. Fallback to RSA if ECC directory is empty or removed
	_ = os.RemoveAll(eccDir)
	fcRSA, fkRSA, ok := DiscoverACMECertIn([]string{acmeBase}, domain)
	if !ok || fcRSA != rsaCert || fkRSA != rsaKey {
		t.Fatalf("expected fallback to RSA cert, got (%s, %s, %v)", fcRSA, fkRSA, ok)
	}
}

// TestAdversarial_Production_SelfSignedBan_Strictness verifies the production ban:
// when AllowSelfSignedCertForTest is false, self-signed certificates are 100% prohibited.
func TestAdversarial_Production_SelfSignedBan_Strictness(t *testing.T) {
	// Case 1: No certs provided and discovery fails -> MUST fail fatal
	cfgProdNoCert := ServerConfig{
		Listen:                     ":2083",
		Domain:                     "prod-strict.aero.test",
		AllowSelfSignedCertForTest: false,
	}
	s1, err := NewServer(cfgProdNoCert)
	if err == nil {
		s1.Close()
		t.Fatal("production server must reject startup without valid TLS certificates")
	}
	if !strings.Contains(err.Error(), "self-signed cert is prohibited") {
		t.Fatalf("expected explicit self-signed prohibition error, got: %v", err)
	}

	// Case 2: Incomplete cert (cert file set, key file missing)
	tmpDir := t.TempDir()
	cFile := filepath.Join(tmpDir, "fullchain.cer")
	_ = os.WriteFile(cFile, []byte("dummy cert"), 0644)

	cfgIncomplete := ServerConfig{
		Listen:                     ":2083",
		Domain:                     "prod-strict.aero.test",
		CertFile:                   cFile,
		KeyFile:                    "",
		AllowSelfSignedCertForTest: false,
	}
	s2, err := NewServer(cfgIncomplete)
	if err == nil {
		s2.Close()
		t.Fatal("expected failure when KeyFile is empty in production")
	}

	// Case 3: Invalid/corrupt cert file
	kFile := filepath.Join(tmpDir, "privkey.key")
	_ = os.WriteFile(kFile, []byte("dummy key"), 0600)

	cfgCorrupt := ServerConfig{
		Listen:                     ":2083",
		Domain:                     "prod-strict.aero.test",
		CertFile:                   cFile,
		KeyFile:                    kFile,
		AllowSelfSignedCertForTest: false,
	}
	s3, err := NewServer(cfgCorrupt)
	if err == nil {
		s3.Close()
		t.Fatal("expected failure when cert/key files are invalid in production")
	}

	// Case 4: AllowSelfSignedCertForTest=true allows self-signed test server
	cfgTest := ServerConfig{
		Listen:                     ":2083",
		Domain:                     "test.aero.local",
		AllowSelfSignedCertForTest: true,
	}
	s4, err := NewServer(cfgTest)
	if err != nil {
		t.Fatalf("test mode with AllowSelfSignedCertForTest=true must succeed, got %v", err)
	}
	defer s4.Close()

	if s4.CertLoader() == nil || s4.CertLoader().CurrentCert() == nil {
		t.Fatal("test server should have an initialized self-signed cert")
	}
}

// TestAdversarial_ZeroPort_URL_Enforcement_And_SubscriptionContract stress-tests
// zero-port formatting and edge subscription quota/expiry/tamper enforcement.
func TestAdversarial_ZeroPort_URL_Enforcement_And_SubscriptionContract(t *testing.T) {
	// 1. Test FormatZeroPortSubURL with hostile inputs
	cases := []struct {
		inputHost string
		slug      string
		expected  string
	}{
		{"example.com:443", "admin", "https://example.com/sub/admin"},
		{"https://example.com:443/extra", "admin", "https://example.com/sub/admin"},
		{"example.com:8443", "admin", "https://example.com/sub/admin"},
		{"example.com:2083", "jacky123456", "https://example.com/sub/jacky123456"},
		{"http://example.com:18080/sub/test", "jacky123456", "https://example.com/sub/jacky123456"},
		{"198.51.100.1:443", "admin", "https://198.51.100.1/sub/admin"},
		{"198.51.100.1:2083", "admin", "https://198.51.100.1/sub/admin"},
		{"[2606:4700::1]:443", "admin", "https://[2606:4700::1]/sub/admin"},
		{"2606:4700::1", "admin", "https://[2606:4700::1]/sub/admin"},
		{"", "admin", "https://127.0.0.1/sub/admin"},
		{"  ", "/slug", "https://127.0.0.1/sub/slug"},
	}

	for _, tc := range cases {
		out := FormatZeroPortSubURL(tc.inputHost, tc.slug)
		if out != tc.expected {
			t.Errorf("FormatZeroPortSubURL(%q, %q) = %q, expected %q", tc.inputHost, tc.slug, out, tc.expected)
		}
		if strings.Contains(out, ":443") || strings.Contains(out, ":2083") || strings.Contains(out, ":8443") {
			t.Errorf("FormatZeroPortSubURL output %q violates Zero-Port mandate!", out)
		}
	}

	// 2. Live HTTP Server tests: /sub/admin, /sub/{userSlug}, quota, and HMAC tampering
	tmpDir := t.TempDir()
	store, _, err := BootstrapSubscription(ServerConfig{
		DataDir:                    tmpDir,
		Listen:                     ":443",
		Domain:                     "edge.aero.test",
		Token:                      "master_token_sec123",
		AllowSelfSignedCertForTest: true,
	}, nil)
	if err != nil {
		t.Fatalf("BootstrapSubscription: %v", err)
	}

	// Check Server Address in bootstrap document: must NOT contain :443
	docJSON, err := store.DocumentJSON()
	if err != nil {
		t.Fatalf("DocumentJSON: %v", err)
	}
	var doc SubDocument
	if err := json.Unmarshal(docJSON, &doc); err != nil {
		t.Fatalf("unmarshal doc: %v", err)
	}
	if len(doc.Servers) > 0 && strings.Contains(doc.Servers[0].Address, ":443") {
		t.Fatalf("bootstrap server address %q contains :443 suffix, violating zero-port mandate", doc.Servers[0].Address)
	}

	handler := &SubHandler{Store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		if !handler.TryServe(w, r) {
			http.NotFound(w, r)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 2a. 匿名 GET /sub/admin 必须 404；管理员订阅只经 /sub/{secret} 提供：
	// 200，userId=admin，expireAt=0，trafficLimitBytes=0
	respAnon, err := http.Get(ts.URL + "/sub/admin")
	if err != nil {
		t.Fatalf("GET /sub/admin: %v", err)
	}
	_ = respAnon.Body.Close()
	if respAnon.StatusCode != http.StatusNotFound {
		t.Fatalf("anonymous GET /sub/admin expected 404, got %d", respAnon.StatusCode)
	}
	respAdmin, err := http.Get(ts.URL + "/sub/" + store.Secret())
	if err != nil {
		t.Fatalf("GET /sub/{secret}: %v", err)
	}
	if respAdmin.StatusCode != http.StatusOK {
		t.Fatalf("GET /sub/{secret} expected 200, got %d", respAdmin.StatusCode)
	}
	bodyAdmin, _ := io.ReadAll(respAdmin.Body)
	_ = respAdmin.Body.Close()

	var adminDoc SubDocument
	if err := json.Unmarshal(bodyAdmin, &adminDoc); err != nil {
		t.Fatalf("unmarshal admin doc: %v", err)
	}
	if adminDoc.UserID != "admin" || adminDoc.ExpireAt != 0 || adminDoc.TrafficLimitBytes != 0 {
		t.Fatalf("admin doc contract violation: UserID=%q, ExpireAt=%d, TrafficLimit=%d", adminDoc.UserID, adminDoc.ExpireAt, adminDoc.TrafficLimitBytes)
	}
	if !VerifySub(adminDoc, []byte("master_token_sec123")) {
		t.Fatal("admin doc signature verification failed against master token")
	}

	// 2b. User Sub: Quota enforcement and Expiry
	userSlug := "jacky888xyz"
	userSub := UserSub{
		Username:          "jacky",
		Slug:              userSlug,
		Token:             "user_tok_999",
		ExpireAt:          time.Now().Add(1 * time.Hour).Unix(),
		TrafficLimitBytes: 1000,
		TrafficUsedBytes:  500,
	}
	if err := store.UpsertUserSub(userSub); err != nil {
		t.Fatalf("UpsertUserSub: %v", err)
	}

	// Active user: 200 OK
	respUser, err := http.Get(ts.URL + "/sub/" + userSlug)
	if err != nil || respUser.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for active user sub, got %d (err: %v)", respUser.StatusCode, err)
	}
	_ = respUser.Body.Close()

	// Record traffic up to exact limit: 1000 bytes
	if err := store.RecordTraffic(userSlug, 500); err != nil {
		t.Fatalf("RecordTraffic: %v", err)
	}

	// Exceeded user: MUST return HTTP 403 Forbidden
	respExceeded, err := http.Get(ts.URL + "/sub/" + userSlug)
	if err != nil || respExceeded.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for quota-exceeded user, got %d (err: %v)", respExceeded.StatusCode, err)
	}
	_ = respExceeded.Body.Close()

	// Expired user: MUST return HTTP 403 Forbidden
	expiredSlug := "expired999abc"
	expiredSub := UserSub{
		Username:          "expired",
		Slug:              expiredSlug,
		Token:             "exp_tok",
		ExpireAt:          time.Now().Add(-10 * time.Minute).Unix(),
		TrafficLimitBytes: 0,
		TrafficUsedBytes:  0,
	}
	if err := store.UpsertUserSub(expiredSub); err != nil {
		t.Fatalf("UpsertUserSub expired: %v", err)
	}
	respExpired, err := http.Get(ts.URL + "/sub/" + expiredSlug)
	if err != nil || respExpired.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for expired user, got %d (err: %v)", respExpired.StatusCode, err)
	}
	_ = respExpired.Body.Close()

	// 2c. HMAC Tampering Detection: changing trafficLimitBytes in signed doc invalidates signature
	validUserDoc := SubDocument{
		Version:           "aero/3.0",
		UserID:            "victim_user",
		ExpireAt:          time.Now().Add(24 * time.Hour).Unix(),
		TrafficLimitBytes: 500,
		Servers:           adminDoc.Servers,
		CreatedAt:         time.Now().Unix(),
	}
	sig := SignSub(validUserDoc, []byte("master_token_sec123"))
	validUserDoc.Signature = sig

	if !VerifySub(validUserDoc, []byte("master_token_sec123")) {
		t.Fatal("valid user doc failed signature verification")
	}

	// Attacker tampers with trafficLimitBytes (e.g. changes 500 -> 999999999)
	tamperedDoc := validUserDoc
	tamperedDoc.TrafficLimitBytes = 999999999
	if VerifySub(tamperedDoc, []byte("master_token_sec123")) {
		t.Fatal("HMAC tampering attack succeeded! Tampered trafficLimitBytes was accepted by VerifySub!")
	}
}

// TestAdversarial_AdminSubsAPI_DualFieldCompatibility tests POST /admin/subs
// unmarshaling with both snake_case and camelCase fields for traffic limits.
func TestAdversarial_AdminSubsAPI_DualFieldCompatibility(t *testing.T) {
	dataDir := t.TempDir()
	subStore, err := NewSubStore(dataDir)
	if err != nil {
		t.Fatalf("NewSubStore: %v", err)
	}
	validator := NewValidator(filepath.Join(dataDir, "nonce.wal"))
	tokenStore, err := OpenTokenStore(dataDir, validator)
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}

	adminKey := "secretKey123"
	adminHandler := NewAdminHandler(adminKey, validator, tokenStore, subStore, nil, nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		if !adminHandler.TryServe(w, r) {
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Ingestion test with snake_case: traffic_limit_bytes, traffic_used_bytes, expire_at
	snakePayload := `{
		"username": "alice",
		"slug": "alice123456",
		"token": "tok_alice",
		"expire_at": 1893456000,
		"traffic_limit_bytes": 1073741824,
		"traffic_used_bytes": 1048576
	}`
	req1, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/subs", strings.NewReader(snakePayload))
	req1.Header.Set("X-Aero-Admin-Key", adminKey)
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil || resp1.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp1.Body)
		t.Fatalf("snake_case POST /admin/subs failed with %d: %s (err: %v)", resp1.StatusCode, string(body), err)
	}
	_ = resp1.Body.Close()

	savedAlice, ok := subStore.GetUserSub("alice123456")
	if !ok {
		t.Fatal("alice123456 not found in store")
	}
	if savedAlice.TrafficLimitBytes != 1073741824 || savedAlice.TrafficUsedBytes != 1048576 || savedAlice.ExpireAt != 1893456000 {
		t.Fatalf("snake_case unmarshaling error: %+v", savedAlice)
	}

	// Ingestion test with camelCase: trafficLimitBytes, trafficUsedBytes, expireAt
	camelPayload := `{
		"username": "bob",
		"slug": "bob654321",
		"token": "tok_bob",
		"expireAt": 1893456000,
		"trafficLimitBytes": 2147483648,
		"trafficUsedBytes": 2097152
	}`
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/subs", strings.NewReader(camelPayload))
	req2.Header.Set("X-Aero-Admin-Key", adminKey)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil || resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("camelCase POST /admin/subs failed with %d: %s (err: %v)", resp2.StatusCode, string(body), err)
	}
	_ = resp2.Body.Close()

	savedBob, ok := subStore.GetUserSub("bob654321")
	if !ok {
		t.Fatal("bob654321 not found in store")
	}
	if savedBob.TrafficLimitBytes != 2147483648 || savedBob.TrafficUsedBytes != 2097152 || savedBob.ExpireAt != 1893456000 {
		t.Fatalf("camelCase unmarshaling error: %+v", savedBob)
	}

	// GET /admin/subs lists users; admin_sub is the unguessable /sub/{secret} (never /sub/admin)
	reqList, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/subs", nil)
	reqList.Header.Set("X-Aero-Admin-Key", adminKey)
	respList, err := http.DefaultClient.Do(reqList)
	if err != nil || respList.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/subs failed with %d: %v", respList.StatusCode, err)
	}
	bodyList, _ := io.ReadAll(respList.Body)
	_ = respList.Body.Close()

	var listResp map[string]any
	if err := json.Unmarshal(bodyList, &listResp); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if want := expectedAdminSubPath(subStore); listResp["admin_sub"] != want {
		t.Fatalf("expected admin_sub=%q, got %v", want, listResp["admin_sub"])
	}
}
