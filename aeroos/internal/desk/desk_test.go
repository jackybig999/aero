package desk

import (
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
