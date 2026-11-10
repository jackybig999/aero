package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newSubExpiryAdmin(t *testing.T) (*AdminHandler, *Validator) {
	t.Helper()
	dir := t.TempDir()
	v := NewValidator()
	t.Cleanup(v.Close)
	ts, err := OpenTokenStore(dir, v)
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	ss, err := NewSubStore(dir)
	if err != nil {
		t.Fatalf("NewSubStore: %v", err)
	}
	return NewAdminHandler("admin_key_expiry", v, ts, ss, nil, nil, nil), v
}

func postSubs(t *testing.T, h *AdminHandler, body map[string]any) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/subs", bytes.NewReader(raw))
	req.Header.Set("X-Aero-Admin-Key", "admin_key_expiry")
	rec := httptest.NewRecorder()
	if !h.TryServe(rec, req) {
		t.Fatal("admin handler did not serve /admin/subs")
	}
	return rec.Code
}

// 回归：中台推送已过期的订阅时，其 token 曾获得 365 天有效期。
func TestSubExpiryAdminUpsertOfExpiredSubDoesNotMountToken(t *testing.T) {
	h, v := newSubExpiryAdmin(t)

	code := postSubs(t, h, map[string]any{
		"username": "alice", "slug": "alice123456", "token": "tok_expired",
		"expire_at": time.Now().Add(-time.Hour).Unix(),
	})
	if code != http.StatusOK {
		t.Fatalf("POST /admin/subs status = %d, want 200", code)
	}
	if v.Validate("tok_expired") {
		t.Fatal("token of an expired subscription is valid")
	}
}

// 订阅从有效变为过期时，其已挂载的 token 必须被移除（在线会话随后由执行器断开）。
func TestSubExpiryAdminUpsertExpiringExistingSubRemovesToken(t *testing.T) {
	h, v := newSubExpiryAdmin(t)

	if code := postSubs(t, h, map[string]any{
		"username": "bob", "slug": "bob1234567", "token": "tok_bob",
		"expire_at": time.Now().Add(24 * time.Hour).Unix(),
	}); code != http.StatusOK {
		t.Fatalf("initial upsert status = %d", code)
	}
	if !v.Validate("tok_bob") {
		t.Fatal("token of an active subscription must be valid")
	}
	if code := postSubs(t, h, map[string]any{
		"username": "bob", "slug": "bob1234567", "token": "tok_bob",
		"expire_at": time.Now().Add(-time.Minute).Unix(),
	}); code != http.StatusOK {
		t.Fatalf("expiring upsert status = %d", code)
	}
	if v.Validate("tok_bob") {
		t.Fatal("token stayed valid after its subscription expired")
	}
}

// 有效订阅的 token 有效期必须与订阅到期时间一致，而不是默认一年。
func TestSubExpiryAdminUpsertActiveSubUsesSubscriptionExpiry(t *testing.T) {
	h, v := newSubExpiryAdmin(t)
	expire := time.Now().Add(48 * time.Hour).Unix()

	if code := postSubs(t, h, map[string]any{
		"username": "carol", "slug": "carol123456", "token": "tok_carol", "expire_at": expire,
	}); code != http.StatusOK {
		t.Fatalf("upsert status = %d", code)
	}
	for _, info := range v.ListTokens() {
		if info.Token != "tok_carol" {
			continue
		}
		if d := info.ExpiresAt.Unix() - expire; d < -5 || d > 5 {
			t.Fatalf("token expires at %v, want about %v", info.ExpiresAt, time.Unix(expire, 0))
		}
		return
	}
	t.Fatal("tok_carol not mounted")
}

// 回归：控制台以过去的日期创建用户时，token 曾获得 100 年有效期。
func TestSubExpiryConsoleRejectsPastExpiry(t *testing.T) {
	cases := []CreateUserRequest{
		{Username: "dave", ExpireAt: time.Now().Add(-time.Hour).Unix()},
		{Username: "dave", ExpireDays: -1},
	}
	for _, req := range cases {
		r := req
		if err := r.ValidateAndNormalize(); err == nil {
			t.Errorf("ValidateAndNormalize(%+v) accepted an expiry in the past", req)
		}
	}
	ok := CreateUserRequest{Username: "dave", ExpireDays: 30}
	if err := ok.ValidateAndNormalize(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}
