package desk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFingerprintGeneration(t *testing.T) {
	fp1 := GenerateFingerprintConfig("test-seed-123", "US", "chrome", "133.0.0.0")
	if fp1 == nil {
		t.Fatal("GenerateFingerprintConfig returned nil")
	}
	if fp1.Timezone != "America/New_York" {
		t.Errorf("expected America/New_York, got %s", fp1.Timezone)
	}

	fp2 := GenerateFingerprintConfig("test-seed-123", "US", "chrome", "133.0.0.0")
	if fp1.UserAgent != fp2.UserAgent || fp1.ScreenWidth != fp2.ScreenWidth {
		t.Errorf("fingerprint generation is not deterministic with same seed")
	}

	script := BuildFingerprintScript(fp1)
	if !strings.Contains(script, "webdriver") {
		t.Errorf("expected script to contain webdriver protection")
	}
}

func TestProxyParsing(t *testing.T) {
	cases := []struct {
		raw      string
		protocol string
		host     string
		port     int
		user     string
		pass     string
	}{
		{"127.0.0.1:8080", "http", "127.0.0.1", 8080, "", ""},
		{"socks5://192.168.1.1:1080", "socks5", "192.168.1.1", 1080, "", ""},
		{"user:pass@10.0.0.1:8888", "http", "10.0.0.1", 8888, "user", "pass"},
		{"1.2.3.4:9999:admin:secret", "http", "1.2.3.4", 9999, "admin", "secret"},
	}

	for _, tc := range cases {
		cfg, err := ParseProxyString(tc.raw)
		if err != nil {
			t.Fatalf("ParseProxyString(%s) failed: %v", tc.raw, err)
		}
		if cfg.Host != tc.host || cfg.Port != tc.port || cfg.Protocol != tc.protocol || cfg.Username != tc.user || cfg.Password != tc.pass {
			t.Errorf("ParseProxyString(%s) mismatch: got %+v", tc.raw, cfg)
		}
	}

	detector := &NoopSysProxyDetector{}
	detected, err := detector.Detect()
	if err != nil || detected.Enabled {
		t.Errorf("NoopSysProxyDetector should return disabled proxy with no error, got: %+v, %v", detected, err)
	}
}

func TestStoreAndUserLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer CloseDB()

	// 1. User registration & authentication
	user, err := RegisterUserWithEmail(db, "alice", "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("RegisterUserWithEmail failed: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("expected username alice, got %s", user.Username)
	}

	count, err := CountUsers(db)
	if err != nil || count != 1 {
		t.Errorf("expected 1 user, got %d (err: %v)", count, err)
	}

	authUser, token, err := AuthenticateUser(db, "alice", "password123")
	if err != nil {
		t.Fatalf("AuthenticateUser failed: %v", err)
	}
	if authUser.ID != user.ID || token == "" {
		t.Errorf("AuthenticateUser returned unexpected values: %+v, token: %s", authUser, token)
	}

	valUser, err := ValidateToken(token)
	if err != nil || valUser.ID != user.ID {
		t.Errorf("ValidateToken failed: %v", err)
	}

	// 2. Encryption and Decryption
	plain := "my-secret-key-data"
	cipher, err := EncryptField(plain, "custom-salt")
	if err != nil {
		t.Fatalf("EncryptField failed: %v", err)
	}
	decrypted, err := DecryptField(cipher, "custom-salt")
	if err != nil || decrypted != plain {
		t.Errorf("DecryptField failed: got %s, want %s (err: %v)", decrypted, plain, err)
	}
}

func TestProfileAndAppService(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "app_test.db")

	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer CloseDB()

	detector := &NoopSysProxyDetector{}
	svc := InitAppService(db, detector, tempDir, 19888)

	req := &CreateProfileRequest{
		Name:          "Test Profile 1",
		Notes:         "automated unit test",
		KernelType:    "chrome",
		KernelVersion: "133",
		Country:       "US",
		Languages:     "en-US,en",
	}

	prof, err := svc.CreateProfileAdvanced(req)
	if err != nil {
		t.Fatalf("CreateProfileAdvanced failed: %v", err)
	}
	if prof.Name != "Test Profile 1" {
		t.Errorf("expected profile name 'Test Profile 1', got %s", prof.Name)
	}

	list, err := svc.ListProfiles()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListProfiles failed: len=%d, err=%v", len(list), err)
	}

	cloned, err := svc.CloneProfile(prof.ID)
	if err != nil {
		t.Fatalf("CloneProfile failed: %v", err)
	}
	if !strings.Contains(cloned.Name, "副本") {
		t.Errorf("expected cloned name to have '副本', got %s", cloned.Name)
	}

	batchRes := svc.BatchDeleteProfiles([]int64{prof.ID, cloned.ID})
	if batchRes["deleted_count"] != 2 {
		t.Errorf("expected 2 deleted profiles, got %v", batchRes["deleted_count"])
	}
}

func TestAuditAndLogger(t *testing.T) {
	logger := NewRingLogger(10)
	logger.Log("INFO", "TEST", "hello world")
	logs := logger.GetLogs()
	if len(logs) != 1 || logs[0].Message != "hello world" {
		t.Errorf("unexpected logs: %+v", logs)
	}

	tempDir := t.TempDir()
	store := NewHistoryStore(tempDir)
	store.Record("browser", "Chrome 133", "launch test", "ok")
	items := store.GetItems()
	if len(items) != 1 || items[0].Name != "Chrome 133" {
		t.Errorf("unexpected history items: %+v", items)
	}
}

func TestAPIMatrix(t *testing.T) {
	tempDir := t.TempDir()
	vault := NewAPIVault(tempDir)
	providers := vault.GetAll()
	if len(providers) == 0 {
		t.Fatal("expected default providers in APIVault")
	}

	vault.SaveKey("openai", "sk-test-key", "https://api.openai.com/v1")
	vault.UpdateStatus("openai", "valid", 120, "12:00:00")

	for _, p := range vault.GetAll() {
		if p.ID == "openai" {
			if p.APIKey != "sk-test-key" || p.Status != "valid" || p.LatencyMS != 120 {
				t.Errorf("unexpected provider data: %+v", p)
			}
		}
	}
}

func TestFingerprintPlatformAndGPUConsistency(t *testing.T) {
	for i := 0; i < 50; i++ {
		seed := fmt.Sprintf("seed-win-chrome-%d", i)
		fp := GenerateFingerprintConfig(seed, "US", "chrome", "133.0.0.0")
		if fp.Platform != "Win32" {
			t.Errorf("expected Platform 'Win32' for Chrome, got %s", fp.Platform)
		}
		if !strings.Contains(fp.UserAgent, "Windows NT") {
			t.Errorf("expected UserAgent with Windows NT, got %s", fp.UserAgent)
		}
		if strings.Contains(fp.WebGLVendor, "Apple") || strings.Contains(fp.WebGLRenderer, "Apple") {
			t.Errorf("Windows fingerprint must NOT contain Apple GPU: vendor=%s, renderer=%s", fp.WebGLVendor, fp.WebGLRenderer)
		}
	}

	for i := 0; i < 50; i++ {
		seed := fmt.Sprintf("seed-win-ff-%d", i)
		fp := GenerateFingerprintConfig(seed, "US", "firefox", "134.0")
		if fp.Platform != "Win32" {
			t.Errorf("expected Platform 'Win32' for Firefox, got %s", fp.Platform)
		}
		if !strings.Contains(fp.UserAgent, "Windows NT") {
			t.Errorf("expected UserAgent with Windows NT, got %s", fp.UserAgent)
		}
		if strings.Contains(fp.WebGLVendor, "Apple") || strings.Contains(fp.WebGLRenderer, "Apple") {
			t.Errorf("Windows Firefox fingerprint must NOT contain Apple GPU: vendor=%s, renderer=%s", fp.WebGLVendor, fp.WebGLRenderer)
		}
	}

	for i := 0; i < 20; i++ {
		seed := fmt.Sprintf("seed-mac-safari-%d", i)
		fp := GenerateFingerprintConfig(seed, "US", "safari", "17.5")
		if fp.Platform != "MacIntel" {
			t.Errorf("expected Platform 'MacIntel' for Safari, got %s", fp.Platform)
		}
		if !strings.Contains(fp.UserAgent, "Macintosh") {
			t.Errorf("expected UserAgent with Macintosh, got %s", fp.UserAgent)
		}
		if !strings.Contains(fp.WebGLVendor, "Apple") || !strings.Contains(fp.WebGLRenderer, "Apple") {
			t.Errorf("Safari fingerprint must contain Apple GPU: vendor=%s, renderer=%s", fp.WebGLVendor, fp.WebGLRenderer)
		}
	}
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestAPIMatrixStatusCodeValidation(t *testing.T) {
	tempDir := t.TempDir()
	vault := NewAPIVault(tempDir)

	var lastReqKeyHeader string
	var lastReqKeyQuery string

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastReqKeyHeader = r.Header.Get("x-goog-api-key")
		lastReqKeyQuery = r.URL.Query().Get("key")

		switch r.URL.Path {
		case "/200":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/401":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		case "/403":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		case "/404":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		case "/500":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server error"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	mockClient := &http.Client{
		Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			mockHandler.ServeHTTP(rec, req)
			return rec.Result(), nil
		}),
	}

	tester := NewTester(vault, "")
	tester.SetHTTPClient(mockClient)

	// 1. Test 200 -> valid
	vault.SaveKey("test_200", "key123", "http://api.matrix.local/200")
	status, _, _ := tester.TestProvider("test_200")
	if status != "valid" {
		t.Errorf("expected status 'valid' for 200 OK, got '%s'", status)
	}

	// 2. Test 401 -> invalid
	vault.SaveKey("test_401", "key123", "http://api.matrix.local/401")
	status, _, _ = tester.TestProvider("test_401")
	if status != "invalid" {
		t.Errorf("expected status 'invalid' for 401 Unauthorized, got '%s'", status)
	}

	// 3. Test 403 -> invalid
	vault.SaveKey("test_403", "key123", "http://api.matrix.local/403")
	status, _, _ = tester.TestProvider("test_403")
	if status != "invalid" {
		t.Errorf("expected status 'invalid' for 403 Forbidden, got '%s'", status)
	}

	// 4. Test 404 -> MUST be 'error', strictly NOT 'valid'
	vault.SaveKey("test_404", "key123", "http://api.matrix.local/404")
	status, _, _ = tester.TestProvider("test_404")
	if status != "error" {
		t.Errorf("expected status 'error' for 404 Not Found, got '%s' (404 MUST NOT be valid)", status)
	}

	// 5. Test 500 -> error
	vault.SaveKey("test_500", "key123", "http://api.matrix.local/500")
	status, _, _ = tester.TestProvider("test_500")
	if status != "error" {
		t.Errorf("expected status 'error' for 500 Server Error, got '%s'", status)
	}

	// 6. Test Gemini authentication parameters (?key= and x-goog-api-key)
	vault.SaveKey("gemini", "gemini-secret-api-key", "http://api.matrix.local/200")
	status, _, _ = tester.TestProvider("gemini")
	if status != "valid" {
		t.Errorf("expected status 'valid' for gemini 200 OK, got '%s'", status)
	}
	if lastReqKeyHeader != "gemini-secret-api-key" {
		t.Errorf("expected x-goog-api-key header to be passed, got '%s'", lastReqKeyHeader)
	}
	if lastReqKeyQuery != "gemini-secret-api-key" {
		t.Errorf("expected ?key= query parameter to be passed, got '%s'", lastReqKeyQuery)
	}
}

func TestClientBridgeNodesAndSelect(t *testing.T) {
	var selectedAddr string

	nodeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/nodes":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "ok",
				"nodes": []NodeInfo{
					{
						ID:        "hk-01",
						Name:      "HK IPLC 01",
						Address:   "1.2.3.4:443",
						SNI:       "hk01.aero.net",
						Active:    true,
						Reachable: true,
						LatencyMs: 38,
					},
					{
						ID:        "jp-01",
						Name:      "Tokyo BGP 01",
						Address:   "5.6.7.8:443",
						SNI:       "jp01.aero.net",
						Active:    false,
						Reachable: true,
						LatencyMs: 145,
					},
				},
			})
		case "/api/v1/nodes/probe":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "ok",
				"nodes": []NodeInfo{
					{
						ID:        "hk-01",
						Name:      "HK IPLC 01",
						Address:   "1.2.3.4:443",
						SNI:       "hk01.aero.net",
						Active:    true,
						Reachable: true,
						LatencyMs: 35,
					},
					{
						ID:        "jp-01",
						Name:      "Tokyo BGP 01",
						Address:   "5.6.7.8:443",
						SNI:       "jp01.aero.net",
						Active:    false,
						Reachable: true,
						LatencyMs: 120,
					},
				},
			})
		case "/api/v1/nodes/select":
			var req struct {
				Address string `json:"address"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			selectedAddr = req.Address
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "ok",
				"active": req.Address,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	bridge := NewClientBridge("http://127.0.0.1:19877")
	bridge.SetHTTPClient(&http.Client{
		Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			nodeHandler.ServeHTTP(rec, req)
			return rec.Result(), nil
		}),
	})

	// 1. GetNodes
	nodes, err := bridge.GetNodes()
	if err != nil {
		t.Fatalf("GetNodes failed: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Name != "HK IPLC 01" || !nodes[0].Active || nodes[0].LatencyMs != 38 {
		t.Errorf("unexpected node 0: %+v", nodes[0])
	}

	// 2. ProbeNodes
	probed, err := bridge.ProbeNodes()
	if err != nil {
		t.Fatalf("ProbeNodes failed: %v", err)
	}
	if len(probed) != 2 || probed[0].LatencyMs != 35 {
		t.Errorf("unexpected probed nodes: %+v", probed)
	}

	// 3. SelectNode
	err = bridge.SelectNode("5.6.7.8:443")
	if err != nil {
		t.Fatalf("SelectNode failed: %v", err)
	}
	if selectedAddr != "5.6.7.8:443" {
		t.Errorf("expected selectedAddr '5.6.7.8:443', got '%s'", selectedAddr)
	}
}

func TestProfileMultiUserIsolationAndExportImport(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "multiuser_test.db")

	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer CloseDB()

	detector := &NoopSysProxyDetector{}
	svc := InitAppService(db, detector, tempDir, 19889)

	// User 1 session
	_ = SaveSessionUser(db, 101)
	p1, err := svc.CreateProfileAdvanced(&CreateProfileRequest{
		Name:          "User 101 Profile",
		KernelType:    "chrome",
		KernelVersion: "133",
	})
	if err != nil {
		t.Fatalf("CreateProfileAdvanced for User 101 failed: %v", err)
	}
	if p1.UserID != 101 {
		t.Errorf("expected p1.UserID == 101, got %d", p1.UserID)
	}

	// User 2 session
	_ = SaveSessionUser(db, 202)
	p2, err := svc.CreateProfileAdvanced(&CreateProfileRequest{
		Name:          "User 202 Profile",
		KernelType:    "firefox",
		KernelVersion: "134",
	})
	if err != nil {
		t.Fatalf("CreateProfileAdvanced for User 202 failed: %v", err)
	}
	if p2.UserID != 202 {
		t.Errorf("expected p2.UserID == 202, got %d", p2.UserID)
	}

	// Query under User 2 session: must only return User 202's profiles
	u2Profiles, err := svc.ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles for User 202 failed: %v", err)
	}
	if len(u2Profiles) != 1 || u2Profiles[0].ID != p2.ID {
		t.Errorf("expected only User 202 profile, got: %+v", u2Profiles)
	}

	// Query under User 1 session: must only return User 101's profiles
	_ = SaveSessionUser(db, 101)
	u1Profiles, err := svc.ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles for User 101 failed: %v", err)
	}
	if len(u1Profiles) != 1 || u1Profiles[0].ID != p1.ID {
		t.Errorf("expected only User 101 profile, got: %+v", u1Profiles)
	}

	// Query all (pass 0)
	allProfiles, err := svc.ListProfiles(0)
	if err != nil {
		t.Fatalf("ListProfiles(0) failed: %v", err)
	}
	if len(allProfiles) != 2 {
		t.Errorf("expected 2 total profiles, got %d", len(allProfiles))
	}

	// Test Export and Import
	exportPath := filepath.Join(tempDir, "p1_export.json")
	if err := svc.ExportProfileConfig(p1.ID, exportPath); err != nil {
		t.Fatalf("ExportProfileConfig failed: %v", err)
	}

	imported, err := svc.ImportProfileConfig(exportPath)
	if err != nil {
		t.Fatalf("ImportProfileConfig failed: %v", err)
	}
	if imported.Name != p1.Name || imported.KernelType != p1.KernelType {
		t.Errorf("imported profile mismatch: got %+v, want %+v", imported, p1)
	}
}

func TestBrowserEmbeddedExtensionCreation(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Chrome extension
	chromeExtDir := filepath.Join(tempDir, "chrome_ext")
	dummyScript := "console.log('fp injected');"
	err := BuildChromeFingerprintExtension(chromeExtDir, dummyScript)
	if err != nil {
		t.Fatalf("BuildChromeFingerprintExtension failed: %v", err)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(chromeExtDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read Chrome manifest failed: %v", err)
	}
	if !strings.Contains(string(manifestBytes), `"manifest_version": 3`) ||
		!strings.Contains(string(manifestBytes), `"world": "MAIN"`) {
		t.Errorf("Chrome extension manifest missing required MV3 / MAIN world attributes")
	}

	contentBytes, err := os.ReadFile(filepath.Join(chromeExtDir, "content.js"))
	if err != nil || string(contentBytes) != dummyScript {
		t.Errorf("Chrome extension content.js mismatch: %s", string(contentBytes))
	}

	// 2. Firefox extension
	ffExtDir := filepath.Join(tempDir, "ff_ext")
	xpiPath, err := BuildFirefoxFingerprintExtension(ffExtDir, dummyScript)
	if err != nil {
		t.Fatalf("BuildFirefoxFingerprintExtension failed: %v", err)
	}
	if fi, err := os.Stat(xpiPath); err != nil || fi.Size() == 0 {
		t.Errorf("expected non-empty xpi file at %s", xpiPath)
	}
}
