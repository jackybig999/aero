package client

import (
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
	if w := e.rejectionWait(&EdgeRejectError{Status: 401}, time.Second); w < authRetryMin || 60*time.Second/w >= 5 {
		t.Fatalf("auth wait %v allows 5+ failures per minute", w)
	}
	if w := e.rejectionWait(&EdgeRejectError{Status: 429, RetryAfter: 900 * time.Second}, time.Second); w != 900*time.Second {
		t.Fatalf("429 wait %v", w)
	}
	if w := e.rejectionWait(&EdgeRejectError{Status: 503, Code: "address_pool_exhausted"}, time.Second); w != nodeUnavailableRetry {
		t.Fatalf("node unavailable wait %v", w)
	}
	if w := e.rejectionWait(&EdgeRejectError{Status: 403, Code: "destination_ip_prohibited"}, 2*time.Second); w != 2*time.Second {
		t.Fatalf("other rejection wait %v", w)
	}
	if e.lastErrCode != "EDGE_REJECTED" {
		t.Fatalf("status code %q", e.lastErrCode)
	}
	_ = e.rejectionWait(&EdgeRejectError{Status: 401, Details: "EDGE_AUTH_TOKEN_EXPIRED"}, 0)
	if e.lastErrCode != "EDGE_AUTH_TOKEN_EXPIRED" {
		t.Fatalf("status code %q", e.lastErrCode)
	}
}
