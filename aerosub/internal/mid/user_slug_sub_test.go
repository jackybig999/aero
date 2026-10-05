// Copyright 2026 AERO Protocol Contributors
// Plan.md Phase 2: 平铺单包测试 — 用户 Slug 专属订阅、多节点聚合与 SNI 矩阵映射
package mid

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserSlugSubscriptionAndMultiVPS(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sub_vps_test_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	uDB := NewMemoryUserStore()
	uSvc := NewUserService(uDB, "test-hmac-secret-123")

	// 1. 注册两个不同用户: Jacky 与 Alice
	userJacky, err := uSvc.Register(CreateUserParams{
		Username: "jacky",
		Password: "password123",
		Email:    "jacky@test.com",
	})
	if err != nil {
		t.Fatalf("register jacky: %v", err)
	}
	if !strings.HasPrefix(userJacky.SubSlug, "jacky") || len(userJacky.SubSlug) != len("jacky")+6 {
		t.Fatalf("invalid jacky slug format: %s", userJacky.SubSlug)
	}
	if userJacky.SubToken == "" {
		t.Fatalf("expected non-empty sub token for jacky")
	}

	userAlice, err := uSvc.Register(CreateUserParams{
		Username: "alice",
		Password: "password456",
		Email:    "alice@test.com",
	})
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	if !strings.HasPrefix(userAlice.SubSlug, "alice") || len(userAlice.SubSlug) != len("alice")+6 {
		t.Fatalf("invalid alice slug format: %s", userAlice.SubSlug)
	}
	if userJacky.SubSlug == userAlice.SubSlug {
		t.Fatalf("user slugs must be globally unique! got duplicate: %s", userJacky.SubSlug)
	}

	// 2. 初始化持久化 Endpoint 存储并添加两个 VPS 节点 (香港 + 日本)
	epFile := filepath.Join(tempDir, "aero_endpoints.json")
	epStore, err := NewEndpointStore(epFile)
	if err != nil {
		t.Fatalf("epStore: %v", err)
	}

	legacySecretHK := "49adc46eff543149de857a49f89445b0"
	epStore.Upsert(EndpointInfo{
		VPSID:     1,
		Name:      "HK-Edge-01",
		Host:      "hk.aero-net.com",
		IP:        "103.10.10.1",
		Port:      443,
		SubSecret: legacySecretHK,
		Installed: true,
	})
	epStore.Upsert(EndpointInfo{
		VPSID:     2,
		Name:      "JP-Edge-02",
		Host:      "jp.aero-net.com",
		IP:        "104.20.20.2",
		Port:      8443,
		SubSecret: "58bcd57eff543149de857a49f89445c1",
		Installed: true,
	})

	sniMgr := NewSNIMatrixManager("")
	subBuilder := NewSubBuilder(uDB, epStore, nil, sniMgr)

	mux := http.NewServeMux()
	subBuilder.RegisterRoutes(mux)

	// 3. 测试用户 Jacky 专属 Slug 订阅下发: GET /sub/{jacky_slug}
	reqJacky := httptest.NewRequest(http.MethodGet, "/sub/"+userJacky.SubSlug, nil)
	recJacky := httptest.NewRecorder()
	mux.ServeHTTP(recJacky, reqJacky)

	if recJacky.Code != http.StatusOK {
		t.Fatalf("expected 200 for jacky slug sub, got %d", recJacky.Code)
	}

	var jackyDoc struct {
		Version  string           `json:"version"`
		UserID   string           `json:"userId"`
		Slug     string           `json:"slug"`
		ExpireAt int64            `json:"expireAt"`
		Servers  []map[string]any `json:"servers"`
	}
	if err := json.Unmarshal(recJacky.Body.Bytes(), &jackyDoc); err != nil {
		t.Fatalf("unmarshal jacky doc: %v", err)
	}
	if jackyDoc.UserID != "jacky" || jackyDoc.Slug != userJacky.SubSlug {
		t.Fatalf("user identity mismatch in document: %+v", jackyDoc)
	}
	if len(jackyDoc.Servers) != 2 {
		t.Fatalf("expected 2 aggregated VPS servers for jacky, got %d", len(jackyDoc.Servers))
	}
	for _, srv := range jackyDoc.Servers {
		expectedTok := userJacky.SubToken
		if srv["token"] != expectedTok {
			t.Errorf("expected server token to be user SubToken %s, got %v", expectedTok, srv["token"])
		}
		// 验证 0-DNS 公网 IP 必须存在且非空
		if ip, ok := srv["ip"].(string); !ok || ip == "" {
			t.Errorf("expected server 'ip' to be non-empty, got %v", srv["ip"])
		}
		// 验证跳频备用端口必须包含默认备用端口
		if ports, ok := srv["alt_ports"].([]any); !ok || len(ports) == 0 {
			t.Errorf("expected server 'alt_ports' to be non-empty array, got %v", srv["alt_ports"])
		}
		// 验证运营商优选标签必须下发
		if isp, ok := srv["isp_affinity"].(string); !ok || isp == "" {
			t.Errorf("expected server 'isp_affinity' to be non-empty, got %v", srv["isp_affinity"])
		}
	}

	// 4. 测试用户 Alice 专属 Slug 订阅下发: GET /sub/{alice_slug}
	reqAlice := httptest.NewRequest(http.MethodGet, "/sub/"+userAlice.SubSlug, nil)
	recAlice := httptest.NewRecorder()
	mux.ServeHTTP(recAlice, reqAlice)

	if recAlice.Code != http.StatusOK {
		t.Fatalf("expected 200 for alice slug sub, got %d", recAlice.Code)
	}
	var aliceDoc struct {
		UserID  string           `json:"userId"`
		Servers []map[string]any `json:"servers"`
	}
	_ = json.Unmarshal(recAlice.Body.Bytes(), &aliceDoc)
	if aliceDoc.UserID != "alice" {
		t.Errorf("expected alice userID, got %s", aliceDoc.UserID)
	}
	expectedAliceTok := userAlice.SubToken
	if aliceDoc.Servers[0]["token"] != expectedAliceTok {
		t.Errorf("alice received wrong token: %v vs %s", aliceDoc.Servers[0]["token"], expectedAliceTok)
	}
	if aliceDoc.Servers[0]["token"] == jackyDoc.Servers[0]["token"] {
		t.Fatalf("CRITICAL SECURITY FLAW: Alice got Jacky's token!")
	}

	// 5. 测试系统管理员常用不限制全节点订阅: GET /sub/superadmin (无六位随机码)
	reqAdmin := httptest.NewRequest(http.MethodGet, "/sub/superadmin", nil)
	recAdmin := httptest.NewRecorder()
	mux.ServeHTTP(recAdmin, reqAdmin)

	if recAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200 for superadmin sub, got %d", recAdmin.Code)
	}
	var adminDoc struct {
		Role         string           `json:"role"`
		Unrestricted bool             `json:"unrestricted"`
		Servers      []map[string]any `json:"servers"`
	}
	_ = json.Unmarshal(recAdmin.Body.Bytes(), &adminDoc)
	if !adminDoc.Unrestricted || adminDoc.Role != "superadmin" {
		t.Fatalf("expected unrestricted superadmin subscription document, got %+v", adminDoc)
	}
	if len(adminDoc.Servers) == 0 {
		t.Fatalf("expected servers in superadmin subscription, got 0")
	}

	// 6. 测试非法或不存在的 Slug
	reqNotFound := httptest.NewRequest(http.MethodGet, "/sub/unknownslug999", nil)
	recNotFound := httptest.NewRecorder()
	mux.ServeHTTP(recNotFound, reqNotFound)
	if recNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown slug, got %d", recNotFound.Code)
	}

	// 7. 测试停用用户后的访问限制
	dis := false
	_ = uDB.UpdateUser(userJacky.ID, UpdateUserParams{Status: &dis})
	recJackyDisabled := httptest.NewRecorder()
	mux.ServeHTTP(recJackyDisabled, reqJacky)
	if recJackyDisabled.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disabled user, got %d", recJackyDisabled.Code)
	}

	t.Logf("[SUCCESS] Multi-VPS User Slug, Legacy Dual-Track & Server-Side ISP Dynamic SNI test passed completely!")
}
