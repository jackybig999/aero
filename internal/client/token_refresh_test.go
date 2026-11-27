// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

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
// 处理器按请求序号发 token：第 1 次（初始导入）发旧的，之后都发新的。初始导入时 Apply 会唤醒刷新协程，
// 旧 token 已过 75%，它立刻重拉；这一次与测试线程谁先谁后都不影响结果，不依赖时序。
func TestTokenRefresherRotatesToNewToken(t *testing.T) {
	now := time.Now()
	oldTok := fakeSignedToken(now.Add(-90*time.Minute), now.Add(30*time.Minute), "old") // 已过 75%
	newTok := fakeSignedToken(now, now.Add(24*time.Hour), "new")
	var fetches atomic.Int32
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()
	useSubHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := newTok
		if fetches.Add(1) == 1 {
			tok = oldTok
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"aero/3.0","servers":[{"name":"n1","host":"198.51.100.7","address":"198.51.100.7:443","ip":"198.51.100.7","token":%q,"sni":"n1.example.com","protocol":"connect-ip"}]}`, tok)
	}))

	eng := NewEngine()
	defer eng.Close()
	applied, err := eng.LoadAndApplySubscription("https://sub.aero.test/sub/x")
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if applied.PrimaryToken != oldTok {
		t.Fatal("initial import did not carry the old token")
	}
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
