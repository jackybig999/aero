// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseProxyStatusAndRejection(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{}}
	resp.Header.Set("Proxy-Status", `aero; error=proxy_authorization_required; details="EDGE_AUTH_TOKEN_EXPIRED"`)
	r := rejectionFrom("connect-ip", resp)
	if !r.AuthFailure() || r.Code != "proxy_authorization_required" || r.Details != "EDGE_AUTH_TOKEN_EXPIRED" {
		t.Fatalf("%+v", r)
	}
	resp = &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"900"}}}
	if r := rejectionFrom("connect", resp); r.RetryAfter != 900*time.Second || r.AuthFailure() {
		t.Fatalf("%+v", r)
	}
	resp = &http.Response{StatusCode: 503, Header: http.Header{"Proxy-Status": {`aero; error=connect_ip_disabled; details="CONNECT-IP is disabled on this node"`}}}
	if r := rejectionFrom("connect-ip", resp); !r.NodeUnavailable() {
		t.Fatalf("%+v", r)
	}
	if code, details := parseProxyStatus(`aero; error=destination_ip_prohibited; details="private, ok"`); code != "destination_ip_prohibited" || details != "private, ok" {
		t.Fatalf("%q %q", code, details)
	}
}

// 401 之后本会话的请求在本地直接失败（不再发往 edge），刷新回调只触发一次。
func TestSessionFailsFastAfterAuthRejection(t *testing.T) {
	var calls atomic.Int32
	s := &Session{onAuthFailure: func() { calls.Add(1) }}
	rej := &EdgeRejectError{Op: "connect", Status: http.StatusUnauthorized, Code: "proxy_authorization_required"}
	if err := s.noteRejection(rej); err != rej {
		t.Fatal("rejection not returned")
	}
	_ = s.noteRejection(&EdgeRejectError{Op: "connect", Status: http.StatusUnauthorized})
	if calls.Load() != 1 {
		t.Fatalf("auth failure hook called %d times, want 1", calls.Load())
	}
	if err := s.checkRejected(); err != rej {
		t.Fatalf("checkRejected = %v", err)
	}
	other := &Session{}
	_ = other.noteRejection(&EdgeRejectError{Status: 403, Code: "destination_ip_prohibited"})
	if other.checkRejected() != nil {
		t.Fatal("a per-destination rejection must not poison the session")
	}
}

// 重连节奏：认证失败至少间隔 15 秒（每分钟少于 5 次，不触发 edge 封禁）；429 按 Retry-After；节点不可用至少 1 分钟。
func TestRejectionWait(t *testing.T) {
	e := &Engine{}
	if w := e.rejectionWait(context.Background(), &EdgeRejectError{Status: 401}, time.Second); w < authRetryMin || 60*time.Second/w >= 5 {
		t.Fatalf("auth wait %v allows 5+ failures per minute", w)
	}
	if w := e.rejectionWait(context.Background(), &EdgeRejectError{Status: 429, RetryAfter: 900 * time.Second}, time.Second); w != 900*time.Second {
		t.Fatalf("429 wait %v", w)
	}
	if w := e.rejectionWait(context.Background(), &EdgeRejectError{Status: 503, Code: "address_pool_exhausted"}, time.Second); w != nodeUnavailableRetry {
		t.Fatalf("node unavailable wait %v", w)
	}
	if w := e.rejectionWait(context.Background(), &EdgeRejectError{Status: 403, Code: "destination_ip_prohibited"}, 2*time.Second); w != 2*time.Second {
		t.Fatalf("other rejection wait %v", w)
	}
	if e.lastErrCode != "EDGE_REJECTED" {
		t.Fatalf("status code %q", e.lastErrCode)
	}
	_ = e.rejectionWait(context.Background(), &EdgeRejectError{Status: 401, Details: "EDGE_AUTH_TOKEN_EXPIRED"}, 0)
	if e.lastErrCode != "EDGE_AUTH_TOKEN_EXPIRED" {
		t.Fatalf("status code %q", e.lastErrCode)
	}
}

// 节点返回“不可用”（503）：记入冷却名单并换到其他可达节点，跳过仍在冷却中的节点；换成功则立即重连。
func TestNodeUnavailableFailsOverSkippingCoolingNodes(t *testing.T) {
	eng := NewEngine()
	addrs := []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443"}
	applied := &Applied{Tokens: map[string]string{}, SNIs: map[string]string{}}
	for i, a := range addrs {
		applied.Servers = append(applied.Servers, ServerConfig{Name: fmt.Sprintf("n%d", i+1), Address: a, Token: "tok", SNI: "n.example.com", IP: a[:len(a)-4]})
		applied.Tokens[a], applied.SNIs[a] = "tok", "n.example.com"
	}
	if err := eng.Apply(applied); err != nil {
		t.Fatal(err)
	}
	eng.sentinel.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) { return &Client{}, nil }
	eng.markNodeUnavailable(addrs[1]) // n2 刚报告过不可用

	w := eng.rejectionWait(context.Background(), &EdgeRejectError{Status: 503, Code: "connect_ip_disabled"}, time.Second)
	if eng.activeAddr != addrs[2] || w != reconnectMinBackoff {
		t.Fatalf("active=%s wait=%v, want switch to %s and immediate reconnect", eng.activeAddr, w, addrs[2])
	}
	if !eng.nodeUnavailable(addrs[0]) || eng.lastErrCode != "EDGE_CONNECT_IP_DISABLED" {
		t.Fatalf("rejected node not cooling (%v) or code %q", eng.nodeUnavailable(addrs[0]), eng.lastErrCode)
	}
	// 所有其他节点都在冷却：不切换，按节点不可用节奏等待
	eng.markNodeUnavailable(addrs[0])
	if w := eng.rejectionWait(context.Background(), &EdgeRejectError{Status: 503, Code: "address_pool_exhausted"}, time.Second); w != nodeUnavailableRetry || eng.activeAddr != addrs[2] {
		t.Fatalf("all cooling: active=%s wait=%v", eng.activeAddr, w)
	}
}
