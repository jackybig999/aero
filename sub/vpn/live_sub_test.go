// Copyright 2026 AERO Protocol Contributors
// Plan.md Phase 2: 平铺端到端测试 — 中台生命周期、用户鉴权与订阅安全下发
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLiveSubPlatform(t *testing.T) {
	tempDir := t.TempDir()
	// 1. 初始化中台内存数据库与服务层
	hmacSecret := "test-hmac-secret-sub-2026"
	userDB := NewMemoryUserStore()
	userSvc := NewUserService(userDB, hmacSecret)

	nodeSvc := NewNodeService()
	billingSvc := NewBillingService()
	_ = billingSvc

	// 2. 种子管理员用户与节点
	adminUser, err := userSvc.Register(CreateUserParams{
		Username: "admin", Password: "adminPassword123", Email: "admin@aero.local", IsStaff: true,
	})
	if err != nil {
		t.Fatalf("failed to register admin: %v", err)
	}
	_ = userDB.SetStaff(adminUser.ID, true)

	testNode, err := nodeSvc.CreateNode("Tokyo-VIP-01", "Asia", "104.28.1.1", "aero", 443, 100, false, 100, 1)
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	_ = testNode

	epStore, err := NewEndpointStore(filepath.Join(tempDir, "endpoints.json"))
	if err != nil {
		t.Fatalf("epStore init failed: %v", err)
	}
	epStore.Upsert(EndpointInfo{
		VPSID:     1,
		Name:      "Tokyo-VIP-01",
		Host:      "tokyo.aero-net.com",
		IP:        "104.28.1.1",
		Port:      443,
		Installed: true,
	})

	sniMgr := NewSNIMatrixManager("")
	subBuilder := NewSubBuilder(userDB, epStore, nil, sniMgr)

	// 3. 构建 API 路由与鉴权网关
	api := http.NewServeMux()
	api.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"product": "vpsserver-aero",
		})
	})
	NewUserHandler(userSvc).RegisterRoutes(api)
	NewNodeHandler(nodeSvc).RegisterRoutes(api)
	subBuilder.RegisterRoutes(api)

	gate := &Gate{Verify: userSvc.VerifyToken, Next: api}
	handler := CORSPermissive(Recover(gate))

	ts := httptest.NewServer(handler)
	defer ts.Close()
	t.Logf("[SUB] Live sub platform listening on %s", ts.URL)

	// 测试 A：健康检查探针
	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatalf("health check request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body["status"] != "ok" {
			t.Fatalf("expected status 'ok', got %v", body["status"])
		}
		t.Logf("[HEALTH] Sub platform /health returned OK")
	})

	// 测试 B：用户登录认证并获取 Bearer Token
	var userToken string
	t.Run("UserLogin", func(t *testing.T) {
		loginReq := map[string]string{
			"username": "admin",
			"password": "adminPassword123",
		}
		reqBytes, _ := json.Marshal(loginReq)
		resp, err := http.Post(ts.URL+"/api/v1/auth/login/", "application/json", bytes.NewReader(reqBytes))
		if err != nil {
			t.Fatalf("login failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for login, got %d", resp.StatusCode)
		}
		var loginResp struct {
			Code int `json:"code"`
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&loginResp)
		if loginResp.Data.Token == "" {
			t.Fatalf("expected non-empty auth token")
		}
		userToken = loginResp.Data.Token
		t.Logf("[AUTH] Login successful, Token: %s...", userToken[:16])
	})

	// 测试 C：客户端拉取专属 Slug 订阅
	t.Run("PullSubscriptionConfig", func(t *testing.T) {
		subURL := ts.URL + "/sub/" + adminUser.SubSlug
		resp, err := http.Get(subURL)
		if err != nil {
			t.Fatalf("fetch subscription failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for subscription config, got %d", resp.StatusCode)
		}

		var subDoc struct {
			UserID  string           `json:"userId"`
			Slug    string           `json:"slug"`
			Servers []map[string]any `json:"servers"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&subDoc); err != nil {
			t.Fatalf("decode subscription response failed: %v", err)
		}

		if subDoc.UserID != "admin" {
			t.Errorf("expected userID admin, got %s", subDoc.UserID)
		}
		if len(subDoc.Servers) == 0 {
			t.Fatalf("expected at least 1 server in subscription")
		}
		server := subDoc.Servers[0]
		if server["name"] != "Tokyo-VIP-01" {
			t.Errorf("expected node Tokyo-VIP-01, got %v", server["name"])
		}

		t.Logf("[SUCCESS] Subscription pulled successfully! Node: %v, Token: %v", server["name"], server["token"])
	})

	// 测试 D：使用鉴权 Token 查询用户列表 (管理接口)
	t.Run("ListUsersWithStaffToken", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/users/", nil)
		if err != nil {
			t.Fatalf("create request failed: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+userToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var listResp struct {
			Code int `json:"code"`
			Data struct {
				Results []User `json:"results"`
				Count   int    `json:"count"`
			} `json:"data"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&listResp)
		if listResp.Data.Count == 0 {
			t.Fatalf("expected at least 1 user, got 0")
		}
		t.Logf("[SUCCESS] Staff token verified! Found %d user(s) in store", listResp.Data.Count)
	})
}
