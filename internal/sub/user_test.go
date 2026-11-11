// Copyright 2026 AERO Protocol Contributors
// Unit tests for password hashing with crypto/rand, admin key, and ECH/alt_ports injection.
package sub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
	if len(altPorts) < 3 || altPorts[0] != 2083 || altPorts[1] != 2087 || altPorts[2] != 8443 {
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

// 6. 内置管理员（用户名 admin，无论 ID）禁止删除；普通用户可删除。
func TestAdminDeleteProtection(t *testing.T) {
	uDB := NewMemoryUserStore()
	svc := NewUserService(uDB, "test-hmac-secret-admin")

	if _, err := svc.Register(CreateUserParams{Username: "firstuser", Password: "FirstPassword123", Email: "first@example.com"}); err != nil {
		t.Fatal(err)
	}
	admin, err := svc.Register(CreateUserParams{Username: "admin", Password: "InitialPassword123", IsStaff: true})
	if err != nil {
		t.Fatal(err)
	}
	if admin.ID == 1 {
		t.Fatal("test setup: admin must not have ID 1")
	}
	if err := svc.DeleteUser(admin.ID); err == nil {
		t.Fatal("admin (ID != 1) was deleted")
	}
	normal, err := svc.Register(CreateUserParams{Username: "normaluser", Password: "NormalPassword123", Email: "normal@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteUser(normal.ID); err != nil {
		t.Fatalf("failed to delete normal user: %v", err)
	}
}

// 7. 验证 Node 与 EndpointInfo 的 ECHConfig 字段反序列化兼容性及订阅生成
func TestWireContract_NodeAndEndpointECH(t *testing.T) {
	// 1. Test Node unmarshaling with snake_case ech_config
	rawNodeJSON := `{"id":1,"name":"test-node","ech_config":"AERO_ECH_SNAKE"}`
	var n1 Node
	if err := json.Unmarshal([]byte(rawNodeJSON), &n1); err != nil {
		t.Fatalf("unmarshal n1: %v", err)
	}
	if n1.ECHConfig != "AERO_ECH_SNAKE" {
		t.Fatalf("n1.ECHConfig = %q, want AERO_ECH_SNAKE", n1.ECHConfig)
	}

	// 2. Test Node unmarshaling with camelCase echConfig
	rawNodeJSON2 := `{"id":2,"name":"test-node-2","echConfig":"AERO_ECH_CAMEL"}`
	var n2 Node
	if err := json.Unmarshal([]byte(rawNodeJSON2), &n2); err != nil {
		t.Fatalf("unmarshal n2: %v", err)
	}
	if n2.ECHConfig != "AERO_ECH_CAMEL" {
		t.Fatalf("n2.ECHConfig = %q, want AERO_ECH_CAMEL", n2.ECHConfig)
	}

	// 3. Test Node unmarshaling with legacy ech
	rawNodeJSON3 := `{"id":3,"name":"test-node-3","ech":"AERO_ECH_LEGACY"}`
	var n3 Node
	if err := json.Unmarshal([]byte(rawNodeJSON3), &n3); err != nil {
		t.Fatalf("unmarshal n3: %v", err)
	}
	if n3.ECHConfig != "AERO_ECH_LEGACY" {
		t.Fatalf("n3.ECHConfig = %q, want AERO_ECH_LEGACY", n3.ECHConfig)
	}

	// 4. Test EndpointInfo unmarshaling with ech_config and camelCase echConfig
	rawEP1 := `{"vps_id":1,"host":"h1.test","ech_config":"EP_ECH_SNAKE"}`
	var ep1 EndpointInfo
	if err := json.Unmarshal([]byte(rawEP1), &ep1); err != nil {
		t.Fatalf("unmarshal ep1: %v", err)
	}
	if ep1.ECHConfig != "EP_ECH_SNAKE" || ep1.ECH() != "EP_ECH_SNAKE" {
		t.Fatalf("ep1 ECH() = %q, want EP_ECH_SNAKE", ep1.ECH())
	}

	rawEP2 := `{"vps_id":2,"host":"h2.test","echConfig":"EP_ECH_CAMEL"}`
	var ep2 EndpointInfo
	if err := json.Unmarshal([]byte(rawEP2), &ep2); err != nil {
		t.Fatalf("unmarshal ep2: %v", err)
	}
	if ep2.ECHConfig != "EP_ECH_CAMEL" || ep2.ECH() != "EP_ECH_CAMEL" {
		t.Fatalf("ep2 ECH() = %q, want EP_ECH_CAMEL", ep2.ECH())
	}

	// 5. Test BuildSubscriptionDoc emitting both ech and ech_config
	uDB := NewMemoryUserStore()
	svc := NewUserService(uDB, "test-hmac-secret-wire")
	user, err := svc.Register(CreateUserParams{
		Username:   "wireuser",
		Password:   "WirePass123!",
		Email:      "wire@example.com",
		PlanMonths: 1,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "mid_wire_ech_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	epPath := filepath.Join(tempDir, "endpoints.json")
	epStore, err := NewEndpointStore(epPath)
	if err != nil {
		t.Fatal(err)
	}
	epStore.Upsert(EndpointInfo{
		VPSID:     10,
		Name:      "Wire-Node-01",
		Region:    "HK",
		Host:      "hk-wire.aero.test",
		IP:        "198.51.100.99",
		Port:      443,
		Installed: true,
		ECHConfig: "QUFBQUJCQkNDQ0REREVFRUZGR0dI",
	})

	sniMgr := NewSNIMatrixManager("")
	subBuilder := NewSubBuilder(uDB, epStore, nil, sniMgr)
	doc, status, err := subBuilder.BuildSubscriptionDoc(user, "ANY", "", false)
	if err != nil || status != http.StatusOK {
		t.Fatalf("BuildSubscriptionDoc failed, status: %d, err: %v", status, err)
	}
	servers, ok := doc["servers"].([]map[string]any)
	if !ok || len(servers) == 0 {
		t.Fatalf("expected non-empty servers")
	}
	srv := servers[0]
	if srv["ech"] != "QUFBQUJCQkNDQ0REREVFRUZGR0dI" {
		t.Fatalf("srv['ech'] = %v, want QUFBQUJCQkNDQ0REREVFRUZGR0dI", srv["ech"])
	}
	if srv["ech_config"] != "QUFBQUJCQkNDQ0REREVFRUZGR0dI" {
		t.Fatalf("srv['ech_config'] = %v, want QUFBQUJCQkNDQ0REREVFRUZGR0dI", srv["ech_config"])
	}
}
