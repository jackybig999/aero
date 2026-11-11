package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// C3 签名 token 接入鉴权（api/token.md §3、§7）。

type signedAuthFixture struct {
	qs   *QUICServer
	priv ed25519.PrivateKey
	now  time.Time
}

// liveConns 让测试用的零值 quic.Conn 视为存活，dead 中的除外。
func liveConns(t *testing.T, dead map[*quic.Conn]bool) {
	t.Helper()
	prev := connAlive
	connAlive = func(c *quic.Conn) bool { return !dead[c] }
	t.Cleanup(func() { connAlive = prev })
}

func newSignedAuthFixture(t *testing.T) *signedAuthFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := parseTokenIssuers(map[string]string{"sub-1": base64.StdEncoding.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	qs := NewQUICServer(NewValidator(), nil, nil, nil, nil)
	t.Cleanup(qs.Close)
	f := &signedAuthFixture{qs: qs, priv: priv, now: time.Now()}
	v := NewTokenVerifier(keys)
	v.now = func() time.Time { return f.now }
	qs.SetTokenVerifier(v)
	return f
}

func (f *signedAuthFixture) token(t *testing.T, uid string, maxDevices int, ttl time.Duration) string {
	t.Helper()
	iat := f.now.Add(-time.Minute).Unix()
	tok, err := SignToken(f.priv, TokenClaims{
		V: 1, Iss: "sub", Kid: "sub-1", UID: uid, JTI: "jti_" + uid + "_0123456789", Tier: "pro",
		Classes: []string{"default"}, MaxDevices: maxDevices, Iat: iat, Exp: iat + int64(ttl/time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// auth 以给定连接（可为 nil）与来源 IP 发起一次鉴权，返回结果与状态码。
func (f *signedAuthFixture) auth(token string, conn *quic.Conn, ip string) (bool, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = ip + ":4000"
	req.Header.Set("Authorization", "Bearer "+token)
	if conn != nil {
		req = req.WithContext(context.WithValue(req.Context(), quicConnKey{}, conn))
	}
	rec := httptest.NewRecorder()
	_, ok := f.qs.authRequest(rec, req)
	return ok, rec
}

func TestSignedTokenAcceptedOnlyWhenEnabled(t *testing.T) {
	f := newSignedAuthFixture(t)
	tok := f.token(t, "user_alice01", 3, 24*time.Hour)
	if ok, rec := f.auth(tok, nil, "203.0.113.10"); !ok {
		t.Fatalf("valid signed token rejected: %d %s", rec.Code, rec.Header().Get("Proxy-Status"))
	}
	f.qs.SetTokenVerifier(nil) // auth_signed_token 关闭
	if ok, _ := f.auth(tok, nil, "203.0.113.11"); ok {
		t.Fatal("signed token accepted while auth_signed_token is off")
	}
	// 被篡改（换签发密钥）
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f2 := newSignedAuthFixture(t)
	f2.priv = other
	if ok, _ := f2.auth(f2.token(t, "user_mallory", 3, time.Hour), nil, "203.0.113.12"); ok {
		t.Fatal("token signed with an unknown key accepted")
	}
}

// 过期是正常情况：401 EXPIRED，且不计入防爆破封禁。
func TestSignedTokenExpiredIsNotJailed(t *testing.T) {
	f := newSignedAuthFixture(t)
	expired := f.token(t, "user_bob0001", 3, time.Hour)
	f.now = f.now.Add(2 * time.Hour)
	for i := 0; i < 30; i++ {
		ok, rec := f.auth(expired, nil, "203.0.113.20")
		if ok || rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("Proxy-Status"), "EDGE_AUTH_TOKEN_EXPIRED") {
			t.Fatalf("expired token: ok=%v code=%d status=%q", ok, rec.Code, rec.Header().Get("Proxy-Status"))
		}
	}
	if ok, rec := f.auth(f.token(t, "user_bob0001", 3, time.Hour), nil, "203.0.113.20"); !ok {
		t.Fatalf("refreshed token from the same IP rejected after expiries (jailed?): %d", rec.Code)
	}
}

// 本节点设备数（C3 §3 第 7 步，2026-11-11 修订）：达到 max_devices 时接受新连接、断开该 uid 最早的连接；
// 已关闭的连接不占名额；同一连接上的后续请求不受影响；同一连接换 token 拒绝；其他用户互不影响。
func TestSignedTokenDeviceLimitEvictsOldest(t *testing.T) {
	f := newSignedAuthFixture(t)
	dead := map[*quic.Conn]bool{}
	liveConns(t, dead)
	var evicted []*quic.Conn
	prevClose := closeEvictedConn
	closeEvictedConn = func(c *quic.Conn) { evicted = append(evicted, c) }
	t.Cleanup(func() { closeEvictedConn = prevClose })

	tok := f.token(t, "user_carol01", 2, time.Hour)
	c1, c2, c3 := new(quic.Conn), new(quic.Conn), new(quic.Conn)
	for i, c := range []*quic.Conn{c1, c2, c3} {
		if ok, rec := f.auth(tok, c, "203.0.113.30"); !ok {
			t.Fatalf("connection %d rejected: %d", i+1, rec.Code)
		}
	}
	if len(evicted) != 1 || evicted[0] != c1 {
		t.Fatalf("evicted = %v, want only the oldest connection c1", evicted)
	}
	if _, tracked := f.qs.connTracker.Get(c1); tracked {
		t.Fatal("evicted connection still tracked")
	}
	if ok, _ := f.auth(tok, c2, "203.0.113.30"); !ok {
		t.Fatal("follow-up request on a bound connection rejected")
	}
	if len(evicted) != 1 {
		t.Fatal("a follow-up request on an existing connection evicted another one")
	}
	if ok, _ := f.auth(f.token(t, "user_dave001", 2, time.Hour), c2, "203.0.113.30"); ok {
		t.Fatal("a different token accepted on a connection bound to another token")
	}
	if ok, _ := f.auth(f.token(t, "user_erin001", 1, time.Hour), new(quic.Conn), "203.0.113.31"); !ok || len(evicted) != 1 {
		t.Fatal("another user's connection affected carol's devices")
	}
	// 已关闭的连接不占名额：c2 关闭后再来一条，不应再踢掉 c3
	dead[c2] = true
	if ok, _ := f.auth(tok, new(quic.Conn), "203.0.113.30"); !ok || len(evicted) != 1 {
		t.Fatalf("closed connection still counted (evicted=%d)", len(evicted))
	}
}

// 执行器据此断开 token 已过期的已绑定连接（C3 §3：10 秒内断开）。
func TestTokenStillValidForSignedTokens(t *testing.T) {
	f := newSignedAuthFixture(t)
	tok := f.token(t, "user_frank01", 1, time.Hour)
	if !f.qs.tokenStillValid(tok) {
		t.Fatal("live signed token reported invalid")
	}
	f.now = f.now.Add(time.Hour)
	if f.qs.tokenStillValid(tok) {
		t.Fatal("expired signed token reported valid")
	}
	f.qs.SetTokenVerifier(nil)
	f.now = f.now.Add(-time.Hour)
	if f.qs.tokenStillValid(tok) {
		t.Fatal("signed token valid after auth_signed_token turned off")
	}
}

func TestParseTokenIssuers(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := base64.StdEncoding.EncodeToString(pub)
	if _, err := parseTokenIssuers(map[string]string{"sub-1": good, "sub-2": base64.RawURLEncoding.EncodeToString(pub)}); err != nil {
		t.Fatalf("valid issuers rejected: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"empty":     {},
		"bad kid":   {"Sub_1": good},
		"short key": {"sub-1": base64.StdEncoding.EncodeToString(pub[:16])},
		"not b64":   {"sub-1": "%%%"},
	} {
		if _, err := parseTokenIssuers(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
