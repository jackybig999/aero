// Copyright 2026 AERO Protocol Contributors
// Plan.md Phase 2: 平铺测试 — VPS HTTP 路由与 422 校验守卫测试
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVPSHandler_RoutesAndValidation(t *testing.T) {
	box, _ := NewSecretBox()
	memStore := NewMemoryVPSStore()
	svc := NewVPSService(memStore, box, nil)
	h := NewVPSHandler(svc)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// 1. 测试未提供必要参数 -> 422 拦截
	invalidBody, _ := json.Marshal(map[string]any{
		"name": "incomplete",
	})
	req := httptest.NewRequest("POST", "/api/v1/vps/", bytes.NewReader(invalidBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 Unprocessable Entity, got %d", rec.Code)
	}

	// 2. 测试合法添加 VPS
	validBody, _ := json.Marshal(map[string]any{
		"name":         "test-vps",
		"role":         "edge",
		"ip":           "1.2.3.4",
		"domain":       "edge.example.com",
		"ssh_port":     22,
		"ssh_username": "root",
		"ssh_password": "password123",
	})
	req2 := httptest.NewRequest("POST", "/api/v1/vps/", bytes.NewReader(validBody))
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// 3. 测试列表查询
	req3 := httptest.NewRequest("GET", "/api/v1/vps/", nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec3.Code)
	}
	var res map[string]any
	if err := json.NewDecoder(rec3.Body).Decode(&res); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got %v", res["data"])
	}
	results, ok := data["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("expected 1 vps in list, got %d", len(results))
	}
}
