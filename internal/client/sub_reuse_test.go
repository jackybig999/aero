// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// 点“连接”时复用最近已导入的订阅：不再走网络；地址不同、太旧、来自缓存、令牌到刷新点、没导入过都不复用。
func TestReuseAppliedSubscription(t *testing.T) {
	now := time.Now()
	fresh := fakeSignedToken(now, now.Add(24*time.Hour), "fresh")
	due := fakeSignedToken(now.Add(-90*time.Minute), now.Add(30*time.Minute), "due") // 有效期已过 75%
	var fetches atomic.Int32
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()
	useSubHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		tok := fresh
		if r.URL.Path == "/sub/due" {
			tok = due
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"aero/3.0","servers":[{"name":"n1","host":"198.51.100.7","address":"198.51.100.7:443","ip":"198.51.100.7","token":%q,"sni":"n1.example.com","protocol":"connect-ip"}]}`, tok)
	}))
	const src = "https://sub.aero.test/sub/x"
	eng := NewEngine()
	defer eng.Close()

	if n, ok := eng.ReuseAppliedSubscription(src, time.Minute); ok || n != 0 {
		t.Fatalf("从未导入过不应复用: %d %v", n, ok)
	}
	if _, err := eng.LoadAndApplySubscription(src); err != nil {
		t.Fatalf("load: %v", err)
	}
	if fetches.Load() != 1 {
		t.Fatalf("首次导入应拉取 1 次: %d", fetches.Load())
	}

	// 复用：命中且不再请求网络
	for i := 0; i < 3; i++ {
		if n, ok := eng.ReuseAppliedSubscription(src, 10*time.Minute); !ok || n != 1 {
			t.Fatalf("应复用: %d %v", n, ok)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("复用不应触发网络请求: %d", fetches.Load())
	}

	// 地址不同 / 空地址
	if _, ok := eng.ReuseAppliedSubscription("https://sub.aero.test/sub/other", 10*time.Minute); ok {
		t.Error("不同订阅地址不应复用")
	}
	if _, ok := eng.ReuseAppliedSubscription("", 10*time.Minute); ok {
		t.Error("空地址不应复用")
	}

	// 太旧
	eng.mu.Lock()
	eng.subAppliedAt = time.Now().Add(-11 * time.Minute)
	eng.mu.Unlock()
	if _, ok := eng.ReuseAppliedSubscription(src, 10*time.Minute); ok {
		t.Error("超过 maxAge 不应复用")
	}
	eng.mu.Lock()
	eng.subAppliedAt = time.Now()
	eng.mu.Unlock()

	// 来自离线缓存的结果不复用（缓存里的令牌不是新签发的）
	eng.mu.Lock()
	eng.subAppliedFromCache = true
	eng.mu.Unlock()
	if _, ok := eng.ReuseAppliedSubscription(src, 10*time.Minute); ok {
		t.Error("来自缓存的订阅不应复用")
	}
	eng.mu.Lock()
	eng.subAppliedFromCache = false
	eng.mu.Unlock()

	// 令牌到刷新时刻（有效期的 75%）后不复用，交给正常导入换新令牌。
	// 不替换全局的 tokenRefreshNow：后台刷新协程在并发读取它。用已过 75% 的令牌代替。
	eng2 := NewEngine()
	defer eng2.Close()
	const dueSrc = "https://sub.aero.test/sub/due"
	if _, err := eng2.LoadAndApplySubscription(dueSrc); err != nil {
		t.Fatalf("load due: %v", err)
	}
	if _, ok := eng2.ReuseAppliedSubscription(dueSrc, 10*time.Minute); ok {
		t.Error("令牌已到刷新点不应复用")
	}
}

// 订阅 B 的应用失败时，不能把它（或上一个订阅 A 的节点）当作可复用：savedSubURL 先于 Apply 写入，
// 而 Apply 先替换节点列表、切换节点失败时直接返回错误。走真实的 LoadAndApplySubscription 流程。
func TestReuseAppliedSubscriptionNotReusedAfterFailedApply(t *testing.T) {
	now := time.Now()
	tok := fakeSignedToken(now, now.Add(24*time.Hour), "t")
	ClearCachedSubPorts()
	defer ClearCachedSubPorts()
	useSubHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/sub/b" {
			// 节点是域名且没有 ip：切换节点时要解析，下面让解析失败
			fmt.Fprint(w, `{"version":"aero/3.0","servers":[{"name":"nb","host":"b.node.test","address":"b.node.test:443","token":"`+tok+`","sni":"b.node.test","protocol":"connect-ip"}]}`)
			return
		}
		fmt.Fprint(w, `{"version":"aero/3.0","servers":[{"name":"na","host":"198.51.100.8","address":"198.51.100.8:443","ip":"198.51.100.8","token":"`+tok+`","sni":"a.node.test","protocol":"connect-ip"}]}`)
	}))
	const a = "https://sub.aero.test/sub/a"
	const b = "https://sub.aero.test/sub/b"
	eng := NewEngine()
	defer eng.Close()
	eng.resolveIPv4 = func(host string) (net.IP, error) { return nil, errors.New("no such host") }

	if _, err := eng.LoadAndApplySubscription(a); err != nil {
		t.Fatalf("load A: %v", err)
	}
	if _, ok := eng.ReuseAppliedSubscription(a, 10*time.Minute); !ok {
		t.Fatal("A 应用成功后应可复用")
	}

	// 换成 B：拉取成功，但切换节点时解析失败，LoadAndApplySubscription 返回错误
	if _, err := eng.LoadAndApplySubscription(b); err == nil {
		t.Fatal("B 的节点无法解析，应用应失败")
	}
	if _, ok := eng.ReuseAppliedSubscription(b, 10*time.Minute); ok {
		t.Error("B 应用失败（节点列表已被替换成 B 的），不应复用")
	}
	if _, ok := eng.ReuseAppliedSubscription(a, 10*time.Minute); ok {
		t.Error("savedSubURL 已指向 B，A 的地址也不应复用")
	}
}
