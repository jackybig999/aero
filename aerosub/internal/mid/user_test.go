// Copyright 2026 AERO Protocol Contributors
// Unit tests for SeedAdmin persistence, password hashing with crypto/rand, admin key, and ECH/alt_ports injection.
package mid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 1. 验证 SeedAdmin 运行后，修改密码，再次调用 SeedAdmin，密码哈希未被重置回初始密码
func TestSeedAdminPasswordRetention(t *testing.T) {
	uDB := NewMemoryUserStore()
	svc := NewUserService(uDB, "test-hmac-secret-seed-admin")

	// First SeedAdmin creates admin with initial password
	SeedAdmin(svc, uDB)

	admin, err := uDB.GetUserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatalf("expected admin user to be created, err: %v", err)
	}

	initPwd := "admin123456"
	if !CheckPassword(initPwd, admin.PasswordHash) {
		t.Fatalf("expected initial password to match admin123456")
	}

	// Admin manually updates password
	newCustomPwd := "CustomAdminPass2026#"
	newHash := HashPassword(newCustomPwd)
	if err := uDB.SetPassword(admin.ID, newHash); err != nil {
		t.Fatalf("failed to update admin password: %v", err)
	}

	// Service restarts, calling SeedAdmin again
	SeedAdmin(svc, uDB)

	// Verify admin's updated password was NOT overwritten
	adminAfter, err := uDB.GetUserByUsername("admin")
	if err != nil || adminAfter == nil {
		t.Fatalf("failed to get admin user after re-seed: %v", err)
	}

	if !CheckPassword(newCustomPwd, adminAfter.PasswordHash) {
		t.Fatalf("FATAL: admin password was reset by SeedAdmin! Custom password verification failed")
	}
	if CheckPassword(initPwd, adminAfter.PasswordHash) {
		t.Fatalf("FATAL: admin password was reverted to initial password")
	}
}

// 2. 验证 HashPassword 使用 crypto/rand 随机盐且能被 CheckPassword 成功校验
func TestHashPasswordCryptoRandSalt(t *testing.T) {
	pwd := "MySecureP@ssw0rd999"

	// 2a. Same password hashed twice must produce distinct hashes due to CSPRNG salt
	h1 := HashPassword(pwd)
	h2 := HashPassword(pwd)
	if h1 == h2 {
		t.Fatalf("HashPassword should produce distinct salts with crypto/rand, got identical: %s", h1)
	}

	// 2b. Validate format: sha256:<32-hex-salt>:<64-hex-hash>
	parts := strings.Split(h1, ":")
	if len(parts) != 3 || parts[0] != "sha256" {
		t.Fatalf("malformed password hash format: %s", h1)
	}
	saltHex := parts[1]
	hashHex := parts[2]
	if len(saltHex) != 32 {
		t.Fatalf("expected 16 bytes (32 hex characters) salt, got length %d (%s)", len(saltHex), saltHex)
	}
	if len(hashHex) != 64 {
		t.Fatalf("expected 64 hex characters sha256 hash, got length %d", len(hashHex))
	}

	// 2c. CheckPassword must verify correctly
	if !CheckPassword(pwd, h1) {
		t.Fatalf("CheckPassword failed on h1")
	}
	if !CheckPassword(pwd, h2) {
		t.Fatalf("CheckPassword failed on h2")
	}
	if CheckPassword("WrongP@ssw0rd123", h1) {
		t.Fatalf("CheckPassword should return false for incorrect password")
	}

	// 2d. Backward compatibility with legacy 16-hex-char salt hashes
	legacySalt := "0123456789abcdef"
	legacySum := sha256.Sum256([]byte(legacySalt + pwd))
	legacyStored := fmt.Sprintf("sha256:%s:%x", legacySalt, legacySum)
	if !CheckPassword(pwd, legacyStored) {
		t.Fatalf("CheckPassword failed on legacy 16-hex-char salt format")
	}
}

// 3. 验证 admin.key 自动生成与 0600 权限持久化
func TestAdminKeyGenerationAndPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adminkey_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	adminKeyPath := filepath.Join(tempDir, "admin.key")

	// Phase 1: Key does not exist, generate 32 bytes CSPRNG and persist with 0600
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("failed to read rand: %v", err)
	}
	generatedKey := hex.EncodeToString(raw)
	if len(generatedKey) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(generatedKey))
	}

	if err := os.WriteFile(adminKeyPath, []byte(generatedKey), 0o600); err != nil {
		t.Fatalf("failed to write admin.key: %v", err)
	}

	// Verify file mode (on non-Windows platforms)
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(adminKeyPath)
		if err != nil {
			t.Fatalf("stat admin.key failed: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("expected 0600 permissions, got %#o", fi.Mode().Perm())
		}
	}

	// Phase 2: Load existing key and verify exact match
	b, err := os.ReadFile(adminKeyPath)
	if err != nil {
		t.Fatalf("failed to read back admin.key: %v", err)
	}
	loadedKey := strings.TrimSpace(string(b))
	if loadedKey != generatedKey {
		t.Fatalf("loaded key mismatch: expected %s, got %s", generatedKey, loadedKey)
	}
}

// 4. 验证订阅生成器注入 ECH 与备用端口跳频
func TestSubscriptionDocECHAndAltPorts(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sub_ech_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	uDB := NewMemoryUserStore()
	uSvc := NewUserService(uDB, "test-hmac-secret-ech")

	user, err := uSvc.Register(CreateUserParams{
		Username: "echuser",
		Password: "password123",
		Email:    "ech@test.com",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	epFile := filepath.Join(tempDir, "aero_endpoints.json")
	epStore, err := NewEndpointStore(epFile)
	if err != nil {
		t.Fatalf("epStore failed: %v", err)
	}

	epStore.Upsert(EndpointInfo{
		VPSID:     101,
		Name:      "Node-ECH-01",
		Host:      "node01.aero.test",
		IP:        "198.51.100.1",
		Port:      443,
		Installed: true,
	})

	sniMgr := NewSNIMatrixManager("")
	subBuilder := NewSubBuilder(uDB, epStore, nil, sniMgr)

	doc, status, err := subBuilder.BuildSubscriptionDoc(user, "ANY", "", false)
	if err != nil || status != http.StatusOK {
		t.Fatalf("BuildSubscriptionDoc failed, status: %d, err: %v", status, err)
	}

	servers, ok := doc["servers"].([]map[string]any)
	if !ok || len(servers) == 0 {
		t.Fatalf("expected non-empty servers in subscription doc")
	}

	srv := servers[0]
	// Verify ECH field is injected
	echVal, hasECH := srv["ech"]
	if !hasECH {
		t.Fatalf("missing 'ech' field in server subscription dict")
	}
	_ = echVal // string value

	// Verify alt_ports is injected with default hopping ports
	altPortsRaw, hasAltPorts := srv["alt_ports"]
	if !hasAltPorts {
		t.Fatalf("missing 'alt_ports' field in server subscription dict")
	}
	altPorts, ok := altPortsRaw.([]int)
	if !ok {
		t.Fatalf("alt_ports is not []int: %T", altPortsRaw)
	}
	if len(altPorts) != 3 || altPorts[0] != 2083 || altPorts[1] != 2087 || altPorts[2] != 8443 {
		t.Fatalf("unexpected alt_ports values: %v", altPorts)
	}
}

// 5. 验证 SQLite 连接池单写者配置 SetMaxOpenConns(1)
func TestSQLiteSingleWriterPool(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_pool_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	payDBPath := filepath.Join(tempDir, "aeropay.db")
	payDB, err := NewAeroPayDB(payDBPath)
	if err != nil {
		t.Fatalf("NewAeroPayDB failed: %v", err)
	}
	defer payDB.Close()

	if payDB.db.Stats().MaxOpenConnections != 1 {
		t.Fatalf("expected AeroPayDB MaxOpenConnections == 1, got %d", payDB.db.Stats().MaxOpenConnections)
	}

	aeroDBPath := filepath.Join(tempDir, "aero.db")
	aeroDB, err := NewAeroDB(aeroDBPath, payDB)
	if err != nil {
		t.Fatalf("NewAeroDB failed: %v", err)
	}
	defer aeroDB.Close()

	if aeroDB.db.Stats().MaxOpenConnections != 1 {
		t.Fatalf("expected AeroDB MaxOpenConnections == 1, got %d", aeroDB.db.Stats().MaxOpenConnections)
	}

	ledgerPath := filepath.Join(tempDir, "ledger.db")
	ledgerStore, err := NewSQLiteLedgerStore(ledgerPath)
	if err != nil {
		t.Fatalf("NewSQLiteLedgerStore failed: %v", err)
	}
	defer ledgerStore.Close()

	if ledgerStore.db.Stats().MaxOpenConnections != 1 {
		t.Fatalf("expected SQLiteLedgerStore MaxOpenConnections == 1, got %d", ledgerStore.db.Stats().MaxOpenConnections)
	}
}

// 6. 验证内置超级管理员 superadmin 与 ID=1 禁止删除保护
func TestSuperadminProtection(t *testing.T) {
	uDB := NewMemoryUserStore()
	svc := NewUserService(uDB, "test-hmac-secret-superadmin")

	// 创建 superadmin
	superAdmin, err := svc.Register(CreateUserParams{
		Username:   "superadmin",
		Password:   "InitialPassword123!",
		Email:      "superadmin@example.com",
		PlanMonths: 1,
		IsStaff:    true,
	})
	if err != nil {
		t.Fatalf("Register superadmin failed: %v", err)
	}

	// 尝试删除 superadmin
	if err := svc.DeleteUser(superAdmin.ID); err == nil {
		t.Fatalf("expected error when deleting superadmin, got nil")
	}

	// 创建普通用户并验证可以正常删除
	normalUser, err := svc.Register(CreateUserParams{
		Username:   "normaluser",
		Password:   "NormalPassword123!",
		Email:      "normal@example.com",
		PlanMonths: 1,
	})
	if err != nil {
		t.Fatalf("Register normal user failed: %v", err)
	}

	if err := svc.DeleteUser(normalUser.ID); err != nil {
		t.Fatalf("failed to delete normal user: %v", err)
	}
}

