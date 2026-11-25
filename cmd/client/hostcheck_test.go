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

// 页面从 http://127.0.0.1:<端口>/ 加载后，界面用 fetch 访问同一个服务：同源 POST 带 Origin 与 Sec-Fetch-Site: same-origin，
// Host 是 127.0.0.1:<端口>。完整的中间件链（nonce → CSRF/Host 校验）必须放行，并拒绝跨站与非回环 Host。
func TestBrowserFetchTransportPassesMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	srv := httptest.NewServer(uiNonceMiddleware(csrfProtectMiddleware("session-token", ok)))
	defer srv.Close()
	origin := srv.URL // http://127.0.0.1:<port>

	do := func(method, path string, hdr map[string]string) *http.Response {
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(`{"sub":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	// 浏览器同源 POST
	if r := do("POST", "/api/v1/import", map[string]string{"Origin": origin, "Sec-Fetch-Site": "same-origin"}); r.StatusCode != http.StatusOK {
		t.Errorf("同源 POST 应放行: %d", r.StatusCode)
	}
	// 浏览器同源 GET（不带 Origin）
	if r := do("GET", "/api/v1/status", map[string]string{"Sec-Fetch-Site": "same-origin"}); r.StatusCode != http.StatusOK {
		t.Errorf("同源 GET 应放行: %d", r.StatusCode)
	}
	// 跨站页面发来的请求被拒绝
	if r := do("POST", "/api/v1/import", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("跨站 POST 应拒绝: %d", r.StatusCode)
	}
	// 每个响应都带本进程的标记（窗口加载前用它确认对端是自己）
	resp, err := http.Get(srv.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if uiNonce != "" && resp.Header.Get(uiNonceHeader) != uiNonce {
		t.Errorf("响应缺少本进程标记")
	}
}

// uiURLFor 可能生成 http://[::1]:端口，其 Origin 必须被 CSRF 校验接受，否则所有 POST 都会 403。
func TestIsAllowedLocalURLAcceptsIPv6Loopback(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:19877", "http://localhost:19877", "http://[::1]:19877", "http://[::1]:19877/api"} {
		if !isAllowedLocalURL(u) {
			t.Errorf("%q 应被接受", u)
		}
	}
	for _, u := range []string{"", "https://evil.example", "http://127.0.0.1.evil.example", "http://[::2]:19877", "http://192.168.1.5:19877"} {
		if isAllowedLocalURL(u) {
			t.Errorf("%q 不应被接受", u)
		}
	}
}
