// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsAllowedLocalHost(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "127.0.0.1:19877", "localhost", "LOCALHOST:8080", "[::1]:19877", "::1", "127.1.2.3:80"} {
		if !isAllowedLocalHost(h) {
			t.Errorf("%q 应允许", h)
		}
	}
	for _, h := range []string{"", "example.com", "evil.com:19877", "127.0.0.1.evil.com", "127.0.0.1.evil.com:19877", "192.168.1.5:19877", "0.0.0.0:19877", "localhost.evil.com", "[::2]:80"} {
		if isAllowedLocalHost(h) {
			t.Errorf("%q 不应允许", h)
		}
	}
}

// DNS rebinding / 局域网访问：Host 不是回环的 /api/* 请求一律拒绝（含 GET 与带正确令牌的 POST）；静态资源与 /healthz 不受影响。
func TestCSRFMiddlewareRejectsNonLoopbackHostOnAPI(t *testing.T) {
	const token = "tok"
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	h := csrfProtectMiddleware(token, ok)

	do := func(method, path, host string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(""))
		req.Host = host
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for _, host := range []string{"evil.com:19877", "127.0.0.1.evil.com", "192.168.1.5:19877", "example.com", ""} {
		if rec := do("GET", "/api/v1/subscription", host, nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "HOST_NOT_ALLOWED") {
			t.Errorf("GET /api Host=%q: %d %s，应 403 HOST_NOT_ALLOWED", host, rec.Code, rec.Body.String())
		}
		if rec := do("POST", "/api/v1/import", host, map[string]string{"X-Aero-Client-Token": token}); rec.Code != http.StatusForbidden {
			t.Errorf("带正确令牌的 POST /api Host=%q: %d，应 403", host, rec.Code)
		}
	}
	for _, host := range []string{"127.0.0.1:19877", "localhost:19877", "[::1]:19877", "127.0.0.1"} {
		if rec := do("GET", "/api/v1/subscription", host, nil); rec.Code != http.StatusOK {
			t.Errorf("GET /api Host=%q: %d，应放行", host, rec.Code)
		}
		if rec := do("POST", "/api/v1/import", host, map[string]string{"Origin": "http://127.0.0.1"}); rec.Code != http.StatusOK {
			t.Errorf("本机 Origin 的 POST /api Host=%q: %d，应放行", host, rec.Code)
		}
	}
	// 非 API：静态资源与健康检查不受 Host 影响（行为不变）
	if rec := do("GET", "/", "evil.com", nil); rec.Code != http.StatusOK {
		t.Errorf("GET / 不应受影响: %d", rec.Code)
	}
	if rec := do("GET", "/healthz", "evil.com", nil); rec.Code != http.StatusOK {
		t.Errorf("/healthz 不应受影响: %d", rec.Code)
	}
}
