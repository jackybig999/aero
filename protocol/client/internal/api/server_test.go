package api_test

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aero-protocol/aero-ech/internal/api"
)

func TestAPIServer_CtrlTokenProtection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := api.NewServer(addr)
	secret := "aero_secret_token_1234567890abcdef1234567890abcdef"
	srv.SetCtrlToken(secret)

	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start failed: %v", err)
	}
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	baseURL := "http://" + addr

	// 1. 白名单免密访问：/health
	{
		resp, err := http.Get(baseURL + "/health")
		if err != nil {
			t.Fatalf("GET /health failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for /health, got %d", resp.StatusCode)
		}
	}

	// 2. 白名单免密只读状态：/api/v1/status
	{
		resp, err := http.Get(baseURL + "/api/v1/status")
		if err != nil {
			t.Fatalf("GET /api/v1/status failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for /api/v1/status, got %d", resp.StatusCode)
		}
	}

	// 3. 敏感变异端点无 Token：/api/v1/connect -> 必须 401 拦截
	{
		resp, err := http.Post(baseURL+"/api/v1/connect", "application/json", nil)
		if err != nil {
			t.Fatalf("POST /api/v1/connect failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 unauthorized without token, got %d", resp.StatusCode)
		}
		var errObj map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errObj)
		if errObj["error"] != "unauthorized: invalid or missing ctrl.token" {
			t.Fatalf("unexpected error response: %v", errObj)
		}
	}

	// 4. 敏感变异端点携带 Bearer Token：通过鉴权放行
	{
		req, _ := http.NewRequest("POST", baseURL+"/api/v1/connect", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST with Bearer failed: %v", err)
		}
		defer resp.Body.Close()
		// 鉴权通过后由业务 handler 处理，返回 200 或 500 (无真实 runtime) 但绝不能是 401
		if resp.StatusCode == http.StatusUnauthorized {
			t.Fatalf("unexpected 401 with valid Bearer token")
		}
	}
}
