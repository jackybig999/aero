package edge

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func tokenTestKeys(t *testing.T) (ed25519.PrivateKey, *TokenVerifier, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	v := NewTokenVerifier(map[string]IssuerKey{"sub-2026a": {Issuer: "sub", PublicKey: pub}})
	v.now = func() time.Time { return now }
	return priv, v, now
}

func validClaims(now time.Time) TokenClaims {
	return TokenClaims{
		V: 1, Iss: "sub", Kid: "sub-2026a", UID: "u_12345678", JTI: "jti_0123456789abcdef",
		Tier: "pro", Classes: []string{"default", "ai"}, MaxDevices: 3, QuotaBytes: 200 << 30, BWBps: 6_250_000,
		Iat: now.Unix(), Exp: now.Add(24 * time.Hour).Unix(),
	}
}

func TestTokenSignVerifyRoundTrip(t *testing.T) {
	priv, v, now := tokenTestKeys(t)
	tok, err := SignToken(priv, validClaims(now))
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if !strings.HasPrefix(tok, "aero1.") || strings.Count(tok, ".") != 2 {
		t.Fatalf("token format = %q", tok)
	}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !reflect.DeepEqual(*got, validClaims(now)) {
		t.Fatalf("claims = %+v", got)
	}
}

func TestTokenVerifyRejections(t *testing.T) {
	priv, v, now := tokenTestKeys(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	sign := func(p ed25519.PrivateKey, mutate func(*TokenClaims)) string {
		c := validClaims(now)
		mutate(&c)
		tok, err := SignToken(p, c)
		if err != nil {
			t.Fatalf("SignToken: %v", err)
		}
		return tok
	}
	good := sign(priv, func(*TokenClaims) {})
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1}`)) + "." + parts[2]

	cases := []struct {
		name string
		tok  string
		want error
	}{
		{"empty", "", ErrTokenInvalid},
		{"wrong prefix", "aero2." + parts[1] + "." + parts[2], ErrTokenInvalid},
		{"too long", "aero1." + strings.Repeat("A", 2100) + "." + parts[2], ErrTokenInvalid},
		{"tampered payload", tampered, ErrTokenInvalid},
		{"signed by unknown key", sign(otherPriv, func(*TokenClaims) {}), ErrTokenInvalid},
		{"unknown kid", sign(priv, func(c *TokenClaims) { c.Kid = "nope" }), ErrTokenInvalid},
		{"kid of another issuer", sign(priv, func(c *TokenClaims) { c.Iss = "edge" }), ErrTokenInvalid},
		{"bad version", sign(priv, func(c *TokenClaims) { c.V = 2 }), ErrTokenInvalid},
		{"no classes", sign(priv, func(c *TokenClaims) { c.Classes = nil }), ErrTokenInvalid},
		{"unknown class", sign(priv, func(c *TokenClaims) { c.Classes = []string{"vip"} }), ErrTokenInvalid},
		{"duplicate class", sign(priv, func(c *TokenClaims) { c.Classes = []string{"ai", "ai"} }), ErrTokenInvalid},
		{"zero devices", sign(priv, func(c *TokenClaims) { c.MaxDevices = 0 }), ErrTokenInvalid},
		{"pii-like uid", sign(priv, func(c *TokenClaims) { c.UID = "alice@example.com" }), ErrTokenInvalid},
		{"lifetime over 7 days", sign(priv, func(c *TokenClaims) { c.Exp = c.Iat + 8*86400 }), ErrTokenInvalid},
		{"expired", sign(priv, func(c *TokenClaims) { c.Iat = now.Add(-48 * time.Hour).Unix(); c.Exp = now.Add(-time.Second).Unix() }), ErrTokenExpired},
		{"issued in the future", sign(priv, func(c *TokenClaims) { c.Iat = now.Add(10 * time.Minute).Unix(); c.Exp = now.Add(24 * time.Hour).Unix() }), ErrTokenExpired},
	}
	for _, c := range cases {
		if _, err := v.Verify(c.tok); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}

	// 时钟容差只放宽 iat（签发方时钟略快 ≤ 300 秒），不放宽 exp
	ok := sign(priv, func(c *TokenClaims) { c.Iat = now.Add(4 * time.Minute).Unix(); c.Exp = now.Add(24 * time.Hour).Unix() })
	if _, err := v.Verify(ok); err != nil {
		t.Errorf("iat within 300s skew rejected: %v", err)
	}
}

// 载荷中未知字段被忽略（新增限制项是兼容变更，C3 §6）。
func TestTokenVerifyIgnoresUnknownFields(t *testing.T) {
	priv, v, now := tokenTestKeys(t)
	c := validClaims(now)
	raw, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["future_limit"] = 7
	payload, _ := json.Marshal(m)
	signingInput := "aero1." + base64.RawURLEncoding.EncodeToString(payload)
	tok := signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signingInput)))
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("token with an unknown field rejected: %v", err)
	}
}

// 契约一致性（L0 §4.3）：Go 类型的 json 字段与 api/token.schema.json 一致，必填项一致。
func TestTokenClaimsMatchContractSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "token.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	var fields []string
	optional := map[string]bool{}
	rt := reflect.TypeOf(TokenClaims{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		fields = append(fields, name)
		if strings.Contains(tag, "omitempty") {
			optional[name] = true
		}
	}
	var props []string
	for k := range schema.Properties {
		props = append(props, k)
	}
	sort.Strings(fields)
	sort.Strings(props)
	if !reflect.DeepEqual(fields, props) {
		t.Fatalf("TokenClaims fields %v != schema properties %v", fields, props)
	}
	for _, r := range schema.Required {
		if optional[r] {
			t.Errorf("schema requires %q but TokenClaims marks it omitempty", r)
		}
	}
}
