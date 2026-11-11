package sub

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// C3 跨组件黄金向量：sub 对相同种子与载荷必须产出逐字节相同的 token（edge 侧测试验证同一 token）。
func TestC3GoldenVectorSigning(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "testdata", "c3-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Seed   string      `json:"seed_base64"`
		Claims tokenClaims `json:"claims"`
		Token  string      `json:"token"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	seed, _ := base64.StdEncoding.DecodeString(g.Seed)
	tok, err := signToken(ed25519.NewKeyFromSeed(seed), g.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if tok != g.Token {
		t.Fatalf("sub encoding diverged from the C3 golden vector:\n got  %s\n want %s", tok, g.Token)
	}
}

func decodeClaims(t *testing.T, tok string) tokenClaims {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(tok, tokenPrefix), ".")
	if len(parts) != 2 {
		t.Fatalf("malformed token %q", tok)
	}
	p, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var c tokenClaims
	if err := json.Unmarshal(p, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTokenIssuerKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateTokenIssuer(dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, tokenSigningKeyFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v err=%v, want 0600", fi.Mode().Perm(), err)
	}
	b, err := LoadOrCreateTokenIssuer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.Kid() != b.Kid() || a.PublicKeyBase64() != b.PublicKeyBase64() {
		t.Fatal("key not persisted across restarts")
	}
	if !regexp.MustCompile(`^sub-[0-9a-f]{8}$`).MatchString(a.Kid()) {
		t.Fatalf("kid %q", a.Kid())
	}
	if err := os.WriteFile(filepath.Join(dir, tokenSigningKeyFile), []byte(`{"kid":"BAD","seed":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateTokenIssuer(dir); err == nil {
		t.Fatal("corrupt key file accepted")
	}
}

func TestTokenIssuerIssueForUser(t *testing.T) {
	ti, err := LoadOrCreateTokenIssuer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	ti.now = func() time.Time { return now }
	uidRe := regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

	// 普通用户：24 小时；订阅更早到期时取订阅到期
	u := &User{ID: 7, UUID: "u_ab12cd", ExpireAt: now.Add(48 * time.Hour)}
	tok, exp, err := ti.IssueForUser(u)
	if err != nil {
		t.Fatal(err)
	}
	c := decodeClaims(t, tok)
	if c.Iss != "sub" || c.Kid != ti.Kid() || c.UID != "u_ab12cd-7" || !uidRe.MatchString(c.UID) || c.MaxDevices != defaultMaxDevices ||
		c.Exp != now.Add(tokenTTL).Unix() || !exp.Equal(now.Add(tokenTTL)) || len(c.JTI) < 16 {
		t.Fatalf("claims = %+v", c)
	}
	u.ExpireAt = now.Add(2 * time.Hour)
	tok, _, _ = ti.IssueForUser(u)
	if c := decodeClaims(t, tok); c.Exp != u.ExpireAt.Unix() {
		t.Fatalf("exp %d not capped at subscription expiry %d", c.Exp, u.ExpireAt.Unix())
	}
	u.ExpireAt = now.Add(-time.Minute)
	if _, _, err := ti.IssueForUser(u); err == nil {
		t.Fatal("token issued for an expired subscription")
	}
	// 两次签发 jti 不同
	u.ExpireAt = time.Time{}
	t1, _, _ := ti.IssueForUser(u)
	t2, _, _ := ti.IssueForUser(u)
	if decodeClaims(t, t1).JTI == decodeClaims(t, t2).JTI {
		t.Fatal("jti reused")
	}
	// 管理员：不受订阅到期限制，档位与设备数不同
	admin := &User{ID: 1, UUID: "", IsStaff: true, ExpireAt: now.Add(-time.Hour)}
	tok, _, err = ti.IssueForUser(admin)
	if err != nil {
		t.Fatal(err)
	}
	if c := decodeClaims(t, tok); c.Tier != "admin" || c.MaxDevices != staffMaxDevices || c.UID != "user-00000001" {
		t.Fatalf("admin claims = %+v", c)
	}
	// 签名可用公钥验证
	pub, _ := base64.StdEncoding.DecodeString(ti.PublicKeyBase64())
	i := strings.LastIndexByte(tok, '.')
	sig, _ := base64.RawURLEncoding.DecodeString(tok[i+1:])
	if !ed25519.Verify(pub, []byte(tok[:i]), sig) {
		t.Fatal("signature does not verify with the published public key")
	}
}

// 订阅下发签名 token：开关开启时所有节点同一个 aero1 token；订阅过期 403；关闭时仍为旧 token。
func TestSubscriptionDocSignedTokens(t *testing.T) {
	epStore, err := NewEndpointStore(filepath.Join(t.TempDir(), "endpoints.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range []string{"a.aero.test", "b.aero.test"} {
		if err := epStore.Upsert(EndpointInfo{VPSID: uint64(i + 1), Name: h, Host: h, IP: "198.51.100.1" + string(rune('0'+i)), Port: 443, Installed: true}); err != nil {
			t.Fatal(err)
		}
	}
	ti, err := LoadOrCreateTokenIssuer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sb := NewSubBuilder(NewMemoryUserStore(), epStore, nil, NewSNIMatrixManager(""))
	user := &User{ID: 5, UUID: "u_123456", Username: "tom", SubSlug: "tom123456", SubToken: "opaque_tok", Status: true, ExpireAt: time.Now().Add(72 * time.Hour)}

	tokens := func() []string {
		doc, status, err := sb.BuildSubscriptionDoc(user, "", "", false)
		if err != nil || status != 200 {
			t.Fatalf("BuildSubscriptionDoc: status=%d err=%v", status, err)
		}
		var out []string
		for _, s := range doc["servers"].([]map[string]any) {
			out = append(out, s["token"].(string))
		}
		return out
	}
	if got := tokens(); len(got) != 2 || got[0] != "opaque_tok" {
		t.Fatalf("switch off: tokens = %v, want the opaque token", got)
	}
	sb.SetTokenIssuer(ti, true)
	got := tokens()
	if len(got) != 2 || !strings.HasPrefix(got[0], tokenPrefix) || got[0] != got[1] {
		t.Fatalf("switch on: tokens = %v, want one aero1 token for all servers", got)
	}
	if c := decodeClaims(t, got[0]); c.UID != "u_123456-5" {
		t.Fatalf("uid = %q", c.UID)
	}
	user.ExpireAt = time.Now().Add(-time.Hour)
	if _, status, err := sb.BuildSubscriptionDoc(user, "", "", false); err == nil || status != 403 {
		t.Fatalf("expired subscription: status=%d err=%v, want 403", status, err)
	}
}
