// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUIURLFor(t *testing.T) {
	cases := []struct{ in, want string }{
		{"127.0.0.1:19877", "http://127.0.0.1:19877/"},
		{"localhost:19877", "http://127.0.0.1:19877/"},
		{":19877", "http://127.0.0.1:19877/"},
		{"0.0.0.0:19877", "http://127.0.0.1:19877/"},
		{"[::]:19877", "http://127.0.0.1:19877/"},
		{"[::1]:8080", "http://[::1]:8080/"},
		{"192.168.1.5:19877", ""}, // 非回环地址：不从本机加载
		{"example.com:80", ""},
		{"127.0.0.1", ""}, // 缺端口
		{"", ""},
	}
	for _, c := range cases {
		if got := uiURLFor(c.in); got != c.want {
			t.Errorf("uiURLFor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWaitUIServer(t *testing.T) {
	const nonce = "n0nce-for-test"
	html := func(w http.ResponseWriter, hdr string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if hdr != "" {
			w.Header().Set(uiNonceHeader, hdr)
		}
		_, _ = w.Write([]byte("<html></html>"))
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { html(w, nonce) }))
	defer ok.Close()
	if !waitUIServer(ok.URL+"/", nonce, time.Second) {
		t.Error("返回 HTML 且带本进程标记的服务应判定就绪")
	}

	// 别的程序占了端口：HTML 也是 200，但没有/不是本进程的标记，不能加载
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { html(w, "") }))
	defer other.Close()
	if waitUIServer(other.URL+"/", nonce, 300*time.Millisecond) {
		t.Error("没有本进程标记的页面不应判定就绪")
	}
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { html(w, "someone-else") }))
	defer wrong.Close()
	if waitUIServer(wrong.URL+"/", nonce, 300*time.Millisecond) {
		t.Error("标记不一致不应判定就绪")
	}
	if waitUIServer(ok.URL+"/", "", 300*time.Millisecond) {
		t.Error("空 nonce 不应判定就绪")
	}

	notHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(uiNonceHeader, nonce)
		_, _ = w.Write([]byte("{}"))
	}))
	defer notHTML.Close()
	if waitUIServer(notHTML.URL+"/", nonce, 300*time.Millisecond) {
		t.Error("不是 HTML 的响应不应判定就绪")
	}

	notFound := httptest.NewServer(uiNonceMiddleware(http.NotFoundHandler()))
	defer notFound.Close()
	if waitUIServer(notFound.URL+"/", uiNonce, 300*time.Millisecond) {
		t.Error("404 不应判定就绪")
	}

	// 端口上没有服务：在限定时间内返回 false，不会一直卡住
	closed := httptest.NewServer(http.NotFoundHandler())
	url := closed.URL + "/"
	closed.Close()
	start := time.Now()
	if waitUIServer(url, nonce, 400*time.Millisecond) {
		t.Error("没有服务不应判定就绪")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("等待超出限定时间: %v", time.Since(start))
	}
}

// 中间件给每个响应带上本进程标记；真实组合（中间件 + 页面）下探测通过。
func TestUINonceMiddlewareMarksResponses(t *testing.T) {
	if uiNonce == "" {
		t.Skip("无随机数")
	}
	srv := httptest.NewServer(uiNonceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	})))
	defer srv.Close()
	if !waitUIServer(srv.URL+"/", uiNonce, time.Second) {
		t.Error("经中间件的页面应判定就绪")
	}
}
