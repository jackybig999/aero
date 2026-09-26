package client_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aero-protocol/aero-ech"
)

func TestEnsureCtrlToken(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "ctrl.token")

	// 1. 首次生成
	token1, err := client.EnsureCtrlToken(tempFile)
	if err != nil {
		t.Fatalf("EnsureCtrlToken failed: %v", err)
	}
	if len(token1) < 64 {
		t.Fatalf("expected 64-hex char token, got %d chars", len(token1))
	}

	// 2. 二次加载：必须保持幂等，内容完全一致
	token2, err := client.EnsureCtrlToken(tempFile)
	if err != nil {
		t.Fatalf("EnsureCtrlToken 2nd failed: %v", err)
	}
	if token1 != token2 {
		t.Fatalf("expected persistent token %s, got %s", token1, token2)
	}
}

func TestValidateCtrlToken(t *testing.T) {
	tok := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if !client.ValidateCtrlToken(tok, tok) {
		t.Fatalf("expected valid match")
	}
	if client.ValidateCtrlToken(tok, "wrong-token") {
		t.Fatalf("expected invalid mismatch")
	}
	if client.ValidateCtrlToken(tok, "") {
		t.Fatalf("expected invalid empty")
	}
}

func TestCtrlAuthMiddleware(t *testing.T) {
	validToken := "secure_secret_token_1234567890abcdef"
	nextCalled := false
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := client.CtrlAuthMiddleware(validToken, dummyHandler)

	// 1. 白名单路径 (/health)：无需 Token 直接通过
	{
		nextCalled = false
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !nextCalled {
			t.Fatalf("expected /health to pass without token")
		}
	}

	// 2. 敏感控制路径 (/api/v1/connect) 无 Token：必须 401 拦截
	{
		nextCalled = false
		req := httptest.NewRequest("POST", "/api/v1/connect", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || nextCalled {
			t.Fatalf("expected 401 unauthorized on protected route without token")
		}
	}

	// 3. 敏感控制路径携带 Bearer Token：成功放行
	{
		nextCalled = false
		req := httptest.NewRequest("POST", "/api/v1/connect", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !nextCalled {
			t.Fatalf("expected 200 OK with valid Bearer token")
		}
	}

	// 4. 敏感控制路径携带 X-Ctrl-Token：成功放行
	{
		nextCalled = false
		req := httptest.NewRequest("POST", "/api/v1/connect", nil)
		req.Header.Set("X-Ctrl-Token", validToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !nextCalled {
			t.Fatalf("expected 200 OK with valid X-Ctrl-Token")
		}
	}
}
