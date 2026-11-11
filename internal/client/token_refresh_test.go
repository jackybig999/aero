package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSignedToken 构造只用于客户端读取 iat/exp 的 aero1 token（客户端不验签）。
func fakeSignedToken(iat, exp time.Time, jti string) string {
	p, _ := json.Marshal(map[string]any{"v": 1, "iss": "sub", "jti": jti, "iat": iat.Unix(), "exp": exp.Unix()})
	return "aero1." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
}

func TestTokenLifetimeAndRefreshPoint(t *testing.T) {
	iat := time.Unix(1800000000, 0)
	tok := fakeSignedToken(iat, iat.Add(24*time.Hour), "a")
	gotIat, gotExp, ok := tokenLifetime(tok)
	if !ok || !gotIat.Equal(iat) || !gotExp.Equal(iat.Add(24*time.Hour)) {
		t.Fatalf("tokenLifetime = %v %v %v", gotIat, gotExp, ok)
	}
	if at, ok := nextTokenRefresh(tok); !ok || !at.Equal(iat.Add(18*time.Hour)) {
		t.Fatalf("refresh at %v, want 75%% of lifetime (+18h)", at)
	}
	for _, bad := range []string{"", "opaque_token", "aero1.", "aero1.!!!.x", "aero1." + base64.RawURLEncoding.EncodeToString([]byte(`{"iat":10,"exp":5}`)) + ".x"} {
		if _, _, ok := tokenLifetime(bad); ok {
			t.Errorf("tokenLifetime(%q) accepted", bad)
		}
	}
}

// 有效期过 75% 时自动重新拉取订阅并切换到新 token（引擎字段与全局活跃节点都更新）。
func TestTokenRefresherRotatesToNewToken(t *testing.T) {
	now := time.Now()
	oldTok := fakeSignedToken(now.Add(-90*time.Minute), now.Add(30*time.Minute), "old") // 已过 75%
	newTok := fakeSignedToken(now, now.Add(24*time.Hour), "new")
	var current atomic.Value
	current.Store(oldTok)
	var fetches atomic.Int32
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()
	SetPhysicalDialerHook(newInMemHTTPDialer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"aero/3.0","servers":[{"name":"n1","address":"198.51.100.7:443","ip":"198.51.100.7","token":%q,"sni":"n1.example.com","protocol":"connect-ip"}]}`, current.Load().(string))
	})))
	defer SetPhysicalDialerHook(nil)

	eng := NewEngine()
	defer eng.Close()
	if _, err := eng.LoadAndApplySubscription("http://sub.aero.test/sub/x"); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if _, tok, _, _ := getActiveEdge(); tok != oldTok {
		t.Fatal("initial token not applied")
	}
	current.Store(newTok) // 中台签发了新 token
	eng.kickTokenRefresh()

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, tok, _, _ := getActiveEdge()
		eng.mu.RLock()
		engTok := eng.activeToken
		eng.mu.RUnlock()
		if tok == newTok && engTok == newTok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("token not rotated (fetches=%d, active=%v, engine=%v)", fetches.Load(), tok == newTok, engTok == newTok)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
