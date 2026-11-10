// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupTestConsole creates an in-process edge server with Web Console enabled
func setupTestConsole(t *testing.T, adminKey string) (*Server, string) {
	tempDir := t.TempDir()
	certPEM, keyPEM := generateTestCertPEMForEdge(t, "edge.example.com", "Aero Edge Test")
	certFile := filepath.Join(tempDir, "fullchain.cer")
	keyFile := filepath.Join(tempDir, "edge.example.com.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := ServerConfig{
		Listen:                     "127.0.0.1:0",
		Domain:                     "edge.example.com",
		Token:                      "bootstrap_token_test_123456789012",
		CertFile:                   certFile,
		KeyFile:                    keyFile,
		DataDir:                    tempDir,
		AdminKey:                   adminKey,
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	return srv, tempDir
}

func TestConsoleAuth_ValidKey(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/console?key=secret_key_123", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "AERO Edge Console") {
		t.Errorf("expected body to contain 'AERO Edge Console', got: %s", body)
	}

	// Verify Set-Cookie header sets aero_key HttpOnly; SameSite=Strict
	cookies := rec.Result().Cookies()
	var foundCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "aero_key" {
			foundCookie = c
			break
		}
	}
	if foundCookie == nil {
		t.Fatalf("expected aero_key cookie to be set")
	}
	// Cookie 不得携带原始管理密钥（PROJECT_RULES §5.3）
	if foundCookie.Value == "" || foundCookie.Value == "secret_key_123" || strings.Contains(foundCookie.Value, "secret_key_123") {
		t.Errorf("cookie must hold a derived session value, not the admin key; got %q", foundCookie.Value)
	}
	if !foundCookie.Secure {
		t.Errorf("expected cookie Secure to be true")
	}
	if !foundCookie.HttpOnly {
		t.Errorf("expected cookie HttpOnly to be true")
	}
	if foundCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected cookie SameSite Strict, got %v", foundCookie.SameSite)
	}
}

func TestConsoleAuth_InvalidKey_CamouflageDecoy(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	// Access with wrong key
	req := httptest.NewRequest(http.MethodGet, "/console?key=wrong_key_xyz", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	// Must return HTTP 200 OK camouflage decoy cover page (preventing scanner fingerprinting)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for camouflage decoy, got %d", rec.Code)
	}

	body := rec.Body.String()
	// Must NOT contain console SPA content
	if strings.Contains(body, "AERO Edge Console") {
		t.Errorf("unauthorized response leaked Web Console content!")
	}
	// Must contain cover HTML content
	if !strings.Contains(body, "AERO Edge Cloud") && !strings.Contains(body, "CloudEdge CDN") {
		t.Errorf("expected camouflage cover page, got: %s", body)
	}
}

func TestConsoleAuth_NoKey_CamouflageDecoy(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	// External remote address (non-loopback)
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	req.RemoteAddr = "203.0.113.195:48920"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for camouflage decoy, got %d", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, "AERO Edge Console") {
		t.Errorf("unauthorized response leaked Web Console content!")
	}
}

func TestConsoleAuth_CookieAuth(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	// Access with cookie only, no query param
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	req.RemoteAddr = "203.0.113.195:48920"
	// 先用密钥登录拿到服务端下发的会话 Cookie，再只凭该 Cookie 访问
	login := httptest.NewRecorder()
	srv.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/console?key=secret_key_123", nil))
	var session *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == "aero_key" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("login did not set a session cookie")
	}
	req.AddCookie(&http.Cookie{Name: "aero_key", Value: session.Value})
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "AERO Edge Console") {
		t.Errorf("expected console HTML with valid cookie auth")
	}

	// 把原始密钥直接放进 Cookie 不得通过鉴权（Cookie 只接受派生会话值）
	raw := httptest.NewRequest(http.MethodGet, "/console/api/status", nil)
	raw.AddCookie(&http.Cookie{Name: "aero_key", Value: "secret_key_123"})
	rawRec := httptest.NewRecorder()
	srv.ServeHTTP(rawRec, raw)
	if rawRec.Code != http.StatusForbidden {
		t.Fatalf("raw admin key in cookie: status %d, want 403", rawRec.Code)
	}
}

func TestConsoleAPI_UnauthorizedReturns403(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/console/api/status?key=wrong_key", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for unauthorized API, got %d", rec.Code)
	}
	var errResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if errResp["ok"] != false {
		t.Errorf("expected ok: false in error response")
	}
}

func TestConsoleAPI_Status_ZeroPortUrls(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/console/api/status?key=secret_key_123", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal status json: %v", err)
	}

	if res["ok"] != true {
		t.Errorf("expected ok: true")
	}

	// Zero-port admin subscription URL assertions (Rule 11 & Rule 22)
	adminURL, ok := res["admin_sub_url"].(string)
	if !ok || adminURL == "" {
		t.Fatalf("missing or empty admin_sub_url")
	}
	if strings.Contains(adminURL, ":") {
		u, err := url.Parse(adminURL)
		if err != nil || u.Port() != "" {
			t.Errorf("admin_sub_url MUST be strictly zero-port! Got: %q", adminURL)
		}
	}
	if !strings.HasPrefix(adminURL, "https://") {
		t.Errorf("admin_sub_url must start with https://, got %q", adminURL)
	}
	wantSuffix := "/sub/" + srv.subStore.Secret()
	if srv.subStore.Secret() == "" || !strings.HasSuffix(adminURL, wantSuffix) {
		t.Errorf("admin_sub_url must end with the unguessable %q, got %q", wantSuffix, adminURL)
	}
	if strings.HasSuffix(adminURL, "/sub/admin") {
		t.Errorf("admin_sub_url must not use the anonymous /sub/admin path, got %q", adminURL)
	}

	// Verify cert countdown info is present
	certObj, ok := res["cert"].(map[string]any)
	if !ok {
		t.Fatalf("missing cert object in status response")
	}
	if certObj["status"] != "valid" {
		t.Errorf("expected cert status valid, got %v", certObj["status"])
	}
}

func TestConsoleAPI_Users_Lifecycle(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	// 1. Create user via POST /console/api/users
	createPayload := `{"username":"alice","code":"888xyz","expire_days":30,"traffic_limit_gb":50}`
	req := httptest.NewRequest(http.MethodPost, "/console/api/users?key=secret_key_123", strings.NewReader(createPayload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for create user, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var createRes map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &createRes); err != nil {
		t.Fatalf("unmarshal create user response: %v", err)
	}

	if createRes["slug"] != "alice888xyz" {
		t.Errorf("expected slug 'alice888xyz', got %v", createRes["slug"])
	}
	subURL, ok := createRes["sub_url"].(string)
	if !ok || !strings.HasPrefix(subURL, "https://") || !strings.HasSuffix(subURL, "/sub/alice888xyz") {
		t.Errorf("invalid sub_url format: %q", subURL)
	}
	// Zero-port verification
	if strings.Contains(subURL, ":") {
		u, err := url.Parse(subURL)
		if err == nil && u.Port() != "" {
			t.Errorf("sub_url violated zero-port mandate: %q", subURL)
		}
	}

	// 2. Fetch subscription via GET /sub/alice888xyz
	subReq := httptest.NewRequest(http.MethodGet, "/sub/alice888xyz", nil)
	subRec := httptest.NewRecorder()
	srv.ServeHTTP(subRec, subReq)

	if subRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK fetching created user subscription, got %d", subRec.Code)
	}

	var subDoc SubDocument
	if err := json.Unmarshal(subRec.Body.Bytes(), &subDoc); err != nil {
		t.Fatalf("unmarshal SubDocument: %v", err)
	}
	if subDoc.UserID != "alice" {
		t.Errorf("expected UserID 'alice', got %q", subDoc.UserID)
	}
	if subDoc.TrafficLimitBytes != 50*1024*1024*1024 {
		t.Errorf("expected 50GB traffic limit, got %d", subDoc.TrafficLimitBytes)
	}

	// 3. List users via GET /console/api/users
	listReq := httptest.NewRequest(http.MethodGet, "/console/api/users?key=secret_key_123", nil)
	listRec := httptest.NewRecorder()
	srv.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK listing users, got %d", listRec.Code)
	}
	var listRes struct {
		OK    bool             `json:"ok"`
		Count int              `json:"count"`
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listRes); err != nil {
		t.Fatalf("unmarshal list users: %v", err)
	}
	if listRes.Count != 1 || len(listRes.Users) != 1 {
		t.Fatalf("expected 1 user, got count=%d, len=%d", listRes.Count, len(listRes.Users))
	}
	if listRes.Users[0]["slug"] != "alice888xyz" {
		t.Errorf("expected slug 'alice888xyz' in list, got %v", listRes.Users[0]["slug"])
	}

	// 4. Delete user via DELETE /console/api/users?slug=alice888xyz
	delReq := httptest.NewRequest(http.MethodDelete, "/console/api/users?key=secret_key_123&slug=alice888xyz", nil)
	delRec := httptest.NewRecorder()
	srv.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK deleting user, got %d", delRec.Code)
	}

	// Subsequent fetch of deleted sub must return 404
	subReq2 := httptest.NewRequest(http.MethodGet, "/sub/alice888xyz", nil)
	subRec2 := httptest.NewRecorder()
	srv.ServeHTTP(subRec2, subReq2)

	if subRec2.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found after deletion, got %d", subRec2.Code)
	}
}

func TestWebAssets_EmbeddingAndGzipSize(t *testing.T) {
	if len(consoleHTML) == 0 {
		t.Fatal("consoleHTML is empty")
	}
	if len(consoleCSS) == 0 {
		t.Fatal("consoleCSS is empty")
	}
	if len(consoleJS) == 0 {
		t.Fatal("consoleJS is empty")
	}

	// Gzip all three assets together
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(consoleHTML)
	_, _ = gw.Write(consoleCSS)
	_, _ = gw.Write(consoleJS)
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	totalGzipSize := buf.Len()
	t.Logf("Web Console embedded assets gzipped size: %d bytes (%.2f KB)", totalGzipSize, float64(totalGzipSize)/1024.0)

	// Must be well below 150KB limit per Rule 1 & §5.1
	maxAllowed := 150 * 1024
	if totalGzipSize >= maxAllowed {
		t.Errorf("embedded web assets gzipped size %d exceeds 150KB limit", totalGzipSize)
	}
}

func TestConsoleAPI_WarpToggle(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	// 1. Enabling WARP when port 40000 is closed must return 400 Bad Request
	req := httptest.NewRequest(http.MethodPost, "/console/api/warp/toggle?key=secret_key_123", strings.NewReader(`{"enabled":true,"warp_all":false}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request when port 40000 closed, got %d", rec.Code)
	}

	// 2. Disabling WARP
	reqOff := httptest.NewRequest(http.MethodPost, "/console/api/warp/toggle?key=secret_key_123", strings.NewReader(`{"enabled":false}`))
	reqOff.Header.Set("Content-Type", "application/json")
	recOff := httptest.NewRecorder()
	srv.ServeHTTP(recOff, reqOff)

	if recOff.Code != http.StatusOK {
		t.Errorf("expected 200 OK disabling WARP, got %d", recOff.Code)
	}
	var resOff map[string]any
	_ = json.Unmarshal(recOff.Body.Bytes(), &resOff)
	if resOff["warp_enabled"] != false {
		t.Errorf("expected warp_enabled false")
	}
}

func TestConsoleAPI_Users_Validation(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	// 1. Path traversal or invalid username rejected
	badUserJSON := `{"username":"../admin","expire_days":30,"traffic_limit_gb":50}`
	req := httptest.NewRequest(http.MethodPost, "/console/api/users?key=secret_key_123", strings.NewReader(badUserJSON))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for path traversal username, got %d", rec.Code)
	}

	// 2. Invalid code length rejected
	badCodeJSON := `{"username":"bob","code":"123","expire_days":30,"traffic_limit_gb":50}`
	req2 := httptest.NewRequest(http.MethodPost, "/console/api/users?key=secret_key_123", strings.NewReader(badCodeJSON))
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for 3-char code, got %d", rec2.Code)
	}

	// 3. Unknown fields rejected per Rule 21
	unknownFieldJSON := `{"username":"bob","code":"123456","expire_days":30,"traffic_limit_gb":50,"evil_unknown_field":"hack"}`
	req3 := httptest.NewRequest(http.MethodPost, "/console/api/users?key=secret_key_123", strings.NewReader(unknownFieldJSON))
	rec3 := httptest.NewRecorder()
	srv.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown field, got %d", rec3.Code)
	}
}

func TestConsoleAPI_UserHardening_EmailAndDirectURLAndSignature(t *testing.T) {
	srv, _ := setupTestConsole(t, "secret_key_123")
	defer srv.Close()

	// 1. Create user with email format username & permanent expiration (expire_days = 0)
	payload := `{"username":"alice.dev@company-tech.com","code":"123abc","expire_days":0,"traffic_limit_gb":100}`
	req := httptest.NewRequest(http.MethodPost, "/console/api/users?key=secret_key_123", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for email username, got %d: %s", rec.Code, rec.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}

	slug := res["slug"].(string)
	if slug != "alice.dev@company-tech.com123abc" {
		t.Errorf("expected slug 'alice.dev@company-tech.com123abc', got %v", slug)
	}

	subURL, _ := res["sub_url"].(string)
	directSubURL, _ := res["direct_sub_url"].(string)
	if subURL == "" {
		t.Errorf("expected sub_url to be non-empty")
	}
	if directSubURL == "" {
		t.Errorf("expected direct_sub_url to be non-empty")
	}

	// 2. Fetch user subscription document
	subReq := httptest.NewRequest(http.MethodGet, "/sub/"+slug, nil)
	subRec := httptest.NewRecorder()
	srv.ServeHTTP(subRec, subReq)
	if subRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK fetching sub, got %d", subRec.Code)
	}
	var doc SubDocument
	if err := json.Unmarshal(subRec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal sub doc: %v", err)
	}
	initialSig := doc.Signature
	if initialSig == "" {
		t.Fatalf("expected non-empty initial signature")
	}

	// 3. Record traffic usage and assert signature remains valid
	if err := srv.subStore.RecordTraffic(slug, 1024*1024*50); err != nil {
		t.Fatalf("RecordTraffic: %v", err)
	}

	subReq2 := httptest.NewRequest(http.MethodGet, "/sub/"+slug, nil)
	subRec2 := httptest.NewRecorder()
	srv.ServeHTTP(subRec2, subReq2)
	if subRec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK fetching sub after traffic, got %d", subRec2.Code)
	}
	var doc2 SubDocument
	if err := json.Unmarshal(subRec2.Body.Bytes(), &doc2); err != nil {
		t.Fatalf("unmarshal sub doc2: %v", err)
	}
	if doc2.TrafficUsedBytes != 1024*1024*50 {
		t.Errorf("expected 50MB used traffic, got %d", doc2.TrafficUsedBytes)
	}
	// Signature must be identical because TrafficUsedBytes is not part of subSignBody
	if doc2.Signature != initialSig {
		t.Errorf("traffic accumulation altered signature! before=%s, after=%s", initialSig, doc2.Signature)
	}

	// Token validation: verify that the signature verifies with the user token
	userToken := res["token"].(string)
	if !VerifySub(doc2, []byte(userToken)) {
		t.Errorf("VerifySub failed after traffic accumulation!")
	}
}
