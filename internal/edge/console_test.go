// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025 Aero AI System

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

// testConsoleKey 满足 minAdminKeyLen，旧管理面才会开启。
const testConsoleKey = "secret_key_secret_key_secret_key_123"

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

func TestConsoleAuth_InvalidKey_CamouflageDecoy(t *testing.T) {
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()

	// Access with wrong key
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	req.Header.Set("Authorization", "Bearer wrong_key_xyz")
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
	srv, _ := setupTestConsole(t, testConsoleKey)
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

func TestConsoleAPI_UnauthorizedReturns403(t *testing.T) {
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/console/api/status", nil)
	req.Header.Set("Authorization", "Bearer wrong_key_xyz")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	// 旧管理面未鉴权统一返回伪装站，不再单独暴露 403 JSON
	if strings.Contains(rec.Body.String(), `"ok"`) || strings.Contains(rec.Body.String(), "status") && strings.Contains(rec.Body.String(), "uptime") {
		t.Fatalf("unauthorized API leaked data: %s", rec.Body.String())
	}
}

func TestConsoleAPI_Status_ZeroPortUrls(t *testing.T) {
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/console/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+testConsoleKey)
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
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()

	// 1. Create user via POST /console/api/users
	createPayload := `{"username":"alice","code":"888xyz","expire_days":30,"traffic_limit_gb":50}`
	req := httptest.NewRequest(http.MethodPost, "/console/api/users", strings.NewReader(createPayload))
	req.Header.Set("Authorization", "Bearer "+testConsoleKey)
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
	listReq := httptest.NewRequest(http.MethodGet, "/console/api/users", nil)
	listReq.Header.Set("Authorization", "Bearer "+testConsoleKey)
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
	delReq := httptest.NewRequest(http.MethodDelete, "/console/api/users?slug=alice888xyz", nil)
	delReq.Header.Set("Authorization", "Bearer "+testConsoleKey)
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
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()

	// 1. Enabling WARP when port 40000 is closed must return 400 Bad Request
	req := httptest.NewRequest(http.MethodPost, "/console/api/warp/toggle", strings.NewReader(`{"enabled":true,"warp_all":false}`))
	req.Header.Set("Authorization", "Bearer "+testConsoleKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request when port 40000 closed, got %d", rec.Code)
	}

	// 2. Disabling WARP
	reqOff := httptest.NewRequest(http.MethodPost, "/console/api/warp/toggle", strings.NewReader(`{"enabled":false}`))
	reqOff.Header.Set("Authorization", "Bearer "+testConsoleKey)
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
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()

	// 1. Path traversal or invalid username rejected
	badUserJSON := `{"username":"../admin","expire_days":30,"traffic_limit_gb":50}`
	req := httptest.NewRequest(http.MethodPost, "/console/api/users", strings.NewReader(badUserJSON))
	req.Header.Set("Authorization", "Bearer "+testConsoleKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for path traversal username, got %d", rec.Code)
	}

	// 2. Invalid code length rejected
	badCodeJSON := `{"username":"bob","code":"123","expire_days":30,"traffic_limit_gb":50}`
	req2 := httptest.NewRequest(http.MethodPost, "/console/api/users", strings.NewReader(badCodeJSON))
	req2.Header.Set("Authorization", "Bearer "+testConsoleKey)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for 3-char code, got %d", rec2.Code)
	}

	// 3. Unknown fields rejected per Rule 21
	unknownFieldJSON := `{"username":"bob","code":"123456","expire_days":30,"traffic_limit_gb":50,"evil_unknown_field":"hack"}`
	req3 := httptest.NewRequest(http.MethodPost, "/console/api/users", strings.NewReader(unknownFieldJSON))
	req3.Header.Set("Authorization", "Bearer "+testConsoleKey)
	rec3 := httptest.NewRecorder()
	srv.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown field, got %d", rec3.Code)
	}
}

func TestConsoleAPI_UserHardening_EmailAndDirectURLAndSignature(t *testing.T) {
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()

	// 1. Create user with email format username & permanent expiration (expire_days = 0)
	payload := `{"username":"alice.dev@company-tech.com","code":"123abc","expire_days":0,"traffic_limit_gb":100}`
	req := httptest.NewRequest(http.MethodPost, "/console/api/users", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+testConsoleKey)
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
	assertSubConforms(t, subRec.Body.Bytes())

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
	assertSubConforms(t, subRec2.Body.Bytes())
}

// 新增：旧管理面鉴权加固（M6）。

func legacyReq(method, path, bearer, remote string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if remote != "" {
		req.RemoteAddr = remote
	}
	return req
}

func TestLegacyAdminShortOrEmptyKeyDisabled(t *testing.T) {
	for _, tc := range []struct{ name, key string }{{"short", "short_key_123"}, {"empty-ephemeral", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := setupTestConsole(t, tc.key)
			defer srv.Close()
			key := tc.key
			if len(srv.cfg.AdminKey) >= minAdminKeyLen {
				// 空密钥会被自动生成；此时改写为空以覆盖“空即关闭”
				srv.cfg.AdminKey = ""
				key = "x"
			}
			for _, p := range []string{"/admin/subs", "/console", "/console/api/status", "/health"} {
				rec := httptest.NewRecorder()
				srv.ServeHTTP(rec, legacyReq(http.MethodGet, p, key, "127.0.0.1:1234"))
				body := rec.Body.String()
				if rec.Code != http.StatusOK || strings.Contains(body, "AERO Edge Console") || strings.Contains(body, "uptime_sec") || strings.Contains(body, "subs") {
					t.Fatalf("%s should serve cover page, got %d %.80s", p, rec.Code, body)
				}
			}
		})
	}
}

func TestLegacyAdminQueryKeyRejected(t *testing.T) {
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()
	for _, p := range []string{"/console?key=", "/console?admin_key=", "/admin/subs?key=", "/admin/subs?admin_key=", "/health?admin_key=", "/console/api/status?key="} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, legacyReq(http.MethodGet, p+testConsoleKey, "", "198.51.100.7:1"))
		if strings.Contains(rec.Body.String(), "AERO Edge Console") || strings.Contains(rec.Body.String(), "uptime_sec") || strings.Contains(rec.Body.String(), `"subs"`) {
			t.Fatalf("%s accepted query key", p)
		}
	}
}

func TestLegacyAdminBearerAccepted(t *testing.T) {
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, legacyReq(http.MethodGet, "/console/api/status", testConsoleKey, "198.51.100.8:1"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "{") {
		t.Fatalf("bearer should open console API, got %d %.80s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, legacyReq(http.MethodGet, "/admin/subs", testConsoleKey, "198.51.100.8:1"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count"`) {
		t.Fatalf("bearer should open /admin/subs, got %d %.80s", rec.Code, rec.Body.String())
	}
}

func TestLegacyAdminBadKeyJailBansSameIP(t *testing.T) {
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()
	if srv.quicServer == nil {
		t.Fatal("quic server missing")
	}
	const ip = "198.51.100.9"
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, legacyReq(http.MethodGet, "/admin/subs", "wrong_key_xyz", ip+":4000"))
		if strings.Contains(rec.Body.String(), `"count"`) {
			t.Fatal("wrong key accepted")
		}
	}
	if !srv.quicServer.AuthJail().IsBanned(ip) {
		t.Fatal("ip not banned after 5 failures")
	}
	// 封禁期间正确密钥也被拒
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, legacyReq(http.MethodGet, "/admin/subs", testConsoleKey, ip+":4001"))
	if strings.Contains(rec.Body.String(), `"count"`) {
		t.Fatal("banned ip accepted correct key")
	}
	// 其他 IP 不受影响
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, legacyReq(http.MethodGet, "/admin/subs", testConsoleKey, "198.51.100.10:1"))
	if !strings.Contains(rec.Body.String(), `"count"`) {
		t.Fatal("other ip should not be banned")
	}
	// 无凭据的探测不计入失败
	for i := 0; i < 8; i++ {
		srv.ServeHTTP(httptest.NewRecorder(), legacyReq(http.MethodGet, "/console", "", "198.51.100.11:1"))
	}
	if srv.quicServer.AuthJail().IsBanned("198.51.100.11") {
		t.Fatal("credential-less probes must not be jailed")
	}
}

func TestConsoleShellHiddenPath(t *testing.T) {
	srv, _ := setupTestConsole(t, testConsoleKey)
	defer srv.Close()
	shell := ConsoleShellPath(testConsoleKey)
	if strings.Contains(shell, testConsoleKey) || len(shell) != len("/console/")+16+1 {
		t.Fatalf("unexpected shell path %q", shell)
	}
	// 合法路径：无需任何凭据，返回外壳与静态资源，且不下发 Cookie
	for p, want := range map[string]string{shell: "AERO Edge Console", shell + "console.js": "fetch", shell + "console.css": "{"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, legacyReq(http.MethodGet, p, "", "198.51.100.20:1"))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s: got %d %.60s", p, rec.Code, rec.Body.String())
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatalf("%s must not set cookies", p)
		}
	}
	// 外壳页面里的资源是相对路径，位于隐藏路径之下
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, legacyReq(http.MethodGet, shell, "", ""))
	if strings.Contains(rec.Body.String(), "/console/web/") {
		t.Fatal("shell still references absolute /console/web/ assets")
	}
	// 错误 h、旧路径、未知资源：伪装站
	for _, p := range []string{"/console/0123456789abcdef/", "/console", "/console/", "/console/web/console.js", shell + "nope", "/console/" + shell[len("/console/"):len(shell)-1]} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, legacyReq(http.MethodGet, p, "", "198.51.100.21:1"))
		if strings.Contains(rec.Body.String(), "AERO Edge Console") {
			t.Fatalf("%s leaked console shell", p)
		}
	}
}

func TestConsoleShellAbsentWithShortKey(t *testing.T) {
	srv, _ := setupTestConsole(t, "short_key_123")
	defer srv.Close()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, legacyReq(http.MethodGet, ConsoleShellPath("short_key_123"), "", ""))
	if strings.Contains(rec.Body.String(), "AERO Edge Console") {
		t.Fatal("shell must not exist for short admin key")
	}
}

func TestConsoleURLFromConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(listen string) string {
		p := filepath.Join(dir, "c"+listen+".json")
		b := `{"domain":"n.example.com","admin_key":"` + testConsoleKey + `","listen":"` + listen + `"}`
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	prefix := "https://n.example.com"
	tail := ConsoleShellPath(testConsoleKey) + "#k=" + testConsoleKey
	for listen, want := range map[string]string{":443": prefix + tail, "": prefix + tail, ":8443": prefix + ":8443" + tail, "0.0.0.0:2083": prefix + ":2083" + tail} {
		got, err := ConsoleURLFromConfig(write(listen))
		if err != nil || got != want {
			t.Fatalf("listen %q: got %q err %v, want %q", listen, got, err, want)
		}
	}
	short := filepath.Join(dir, "short.json")
	_ = os.WriteFile(short, []byte(`{"domain":"n.example.com","admin_key":"short"}`), 0o600)
	if _, err := ConsoleURLFromConfig(short); err == nil {
		t.Fatal("short key must error")
	}
}
