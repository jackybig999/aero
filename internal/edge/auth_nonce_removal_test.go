package edge

import (
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// 回归（审查 P0-8）：全局 nonce 表上限 10 万条，单个用户在 2 分钟内发起足够多的首次请求即可
// 耗尽它，之后所有用户鉴权失败。C3 §5：不再要求、也不记录 Aero-Timestamp / Aero-Nonce。
func TestAuthNonceTableCannotBeExhausted(t *testing.T) {
	v := NewValidator()
	v.AddToken("tok_dos", "user", time.Hour)
	v.AddToken("tok_victim", "user", time.Hour)
	qs := NewQUICServer(v, nil, nil, nil, nil)
	defer qs.Close()

	nonce := make([]byte, 32)
	for i := 0; i < 120_000; i++ {
		binary.BigEndian.PutUint64(nonce, uint64(i))
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.50:1000"
		req.Header.Set("Authorization", "Bearer tok_dos")
		req.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
		req.Header.Set("Aero-Nonce", hex.EncodeToString(nonce))
		if _, ok := qs.authRequest(httptest.NewRecorder(), req); !ok {
			t.Fatalf("request %d from a valid token was rejected", i)
		}
	}

	victim := httptest.NewRequest(http.MethodGet, "/x", nil)
	victim.RemoteAddr = "198.51.100.9:2000"
	victim.Header.Set("Authorization", "Bearer tok_victim")
	if _, ok := qs.authRequest(httptest.NewRecorder(), victim); !ok {
		t.Fatal("another user's valid token was rejected after the flood")
	}
}

// 缺失或格式错误的旧头部不影响鉴权；只看 token 本身。
func TestAuthNonceLegacyHeadersIgnored(t *testing.T) {
	v := NewValidator()
	v.AddToken("tok_ok", "user", time.Hour)
	qs := NewQUICServer(v, nil, nil, nil, nil)
	defer qs.Close()

	cases := []struct {
		name, token, ts, nonce string
		want                   bool
	}{
		{"no legacy headers", "tok_ok", "", "", true},
		{"malformed legacy headers", "tok_ok", "not-a-number", "0102", true},
		{"unknown token", "tok_unknown", "", "", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.60:3000"
		req.Header.Set("Authorization", "Bearer "+c.token)
		if c.ts != "" {
			req.Header.Set("Aero-Timestamp", c.ts)
			req.Header.Set("Aero-Nonce", c.nonce)
		}
		rec := httptest.NewRecorder()
		if _, ok := qs.authRequest(rec, req); ok != c.want {
			t.Errorf("%s: ok = %v (status %d), want %v", c.name, ok, rec.Code, c.want)
		}
	}
}
