// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/middleware"
	billingS "github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/service"
	billingStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/store"
	nodeH "github.com/vpn-platform/vpsserver/vpn/internal/modules/node/handler"
	nodeS "github.com/vpn-platform/vpsserver/vpn/internal/modules/node/service"
	nodeStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/node/store"
	subDomain "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/domain"
	subH "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/handler"
	subS "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/service"
	subStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/store"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
	userH "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/handler"
	userS "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/service"
	userStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/store"
)

func TestLiveSubPlatform(t *testing.T) {
	// 1. 初始化中台内存数据库与服务层
	hmacSecret := "test-hmac-secret-sub-2026"
	userDB := userStore.NewMemoryStore()
	userSvc := userS.New(userDB, hmacSecret)

	nodeDB := nodeStore.NewMemoryStore()
	nodeSvc := nodeS.New(nodeDB)

	subscriptionDB := subStore.NewMemoryStore()
	subscriptionSvc := subS.New(subscriptionDB)

	billingSvc := billingS.New(billingStore.NewMemoryStore())
	_ = billingSvc

	// 2. 种子用户与节点
	adminUser, err := userSvc.Register(domain.CreateUserParams{
		Username: "admin", Password: "adminPassword123", Email: "admin@aero.local",
	})
	if err != nil {
		t.Fatalf("failed to register admin: %v", err)
	}
	userDB.SetStaff(adminUser.ID, true)

	testNode, err := nodeSvc.CreateNode("Tokyo-VIP-01", "Asia", "104.28.1.1", "aero", 443, 100, false, 100, 1)
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}

	// 为 admin 创建有效订阅
	clientUUID := "550e8400-e29b-41d4-a716-446655440000"
	subRecord, err := subscriptionSvc.CreateSubscription(
		adminUser.ID,
		testNode.ID,
		clientUUID,
		testNode.Name,
		testNode.IP,
		testNode.Port,
		time.Now().Add(30*24*time.Hour),
	)
	if err != nil {
		t.Fatalf("failed to create subscription: %v", err)
	}
	t.Logf("[SUB] Seeded subscription ID: %d, UUID: %s", subRecord.ID, subRecord.ClientUUID)

	// 3. 构建 API 路由与鉴权网关
	api := http.NewServeMux()
	api.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"product": "vpsserver",
		})
	})
	userH.New(userSvc).RegisterRoutes(api)
	nodeH.New(nodeSvc).RegisterRoutes(api)
	subH.New(subscriptionSvc).RegisterRoutes(api)

	// 挂载中间件与访问网关
	gate := &middleware.Gate{Verify: userSvc.VerifyToken, Next: api}
	handler := middleware.CORSPermissive(middleware.Recover(gate))

	// 4. 启动实时测试 HTTP 服务
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

	// 测试 C：客户端拉取订阅节点配置 (公开订阅端点)
	t.Run("PullSubscriptionConfig", func(t *testing.T) {
		subURL := ts.URL + "/api/v1/subscriptions/config/?uuid=" + clientUUID
		resp, err := http.Get(subURL)
		if err != nil {
			t.Fatalf("fetch subscription failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 for subscription config, got %d: %s", resp.StatusCode, string(body))
		}

		var subResp struct {
			Code int            `json:"code"`
			Data map[string]any `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&subResp); err != nil {
			t.Fatalf("decode subscription response failed: %v", err)
		}

		if subResp.Code != 0 {
			t.Fatalf("expected code 0, got %d", subResp.Code)
		}

		server, _ := subResp.Data["server"].(string)
		if server != "104.28.1.1" {
			t.Errorf("expected node IP 104.28.1.1, got %v", subResp.Data["server"])
		}
		port, _ := subResp.Data["port"].(float64)
		if int(port) != 443 {
			t.Errorf("expected node port 443, got %v", subResp.Data["port"])
		}
		uid, _ := subResp.Data["client_uuid"].(string)
		if uid != clientUUID {
			t.Errorf("expected client UUID %s, got %v", clientUUID, subResp.Data["client_uuid"])
		}

		t.Logf("[SUCCESS] Subscription pulled successfully! Node: %v (%s:%d), Protocol: %v",
			subResp.Data["node_name"], server, int(port), subResp.Data["protocol"])
	})

	// 测试 D：使用鉴权 Token 查询订阅列表 (管理接口)
	t.Run("ListSubscriptionsWithStaffToken", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/subscriptions/", nil)
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
				Results []subDomain.Subscription `json:"results"`
			} `json:"data"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&listResp)
		if len(listResp.Data.Results) == 0 {
			t.Fatalf("expected at least 1 subscription, got 0")
		}
		t.Logf("[SUCCESS] Staff token verified! Found %d subscription(s) in store", len(listResp.Data.Results))
	})
}
