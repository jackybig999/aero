// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestBindOrVerifySemantics(t *testing.T) {
	liveConns(t, nil)
	ct := NewConnTracker()
	if ev, ok := ct.BindOrVerify(nil, "t", "", 0); ok != true || ev != nil {
		t.Fatal("nil connection (tests) must pass")
	}
	c := &quic.Conn{}
	if _, ok := ct.BindOrVerify(c, "tok-a", "", 0); !ok {
		t.Fatal("first bind rejected")
	}
	if _, ok := ct.BindOrVerify(c, "tok-a", "", 0); !ok {
		t.Fatal("same token on the same connection rejected (two class sessions)")
	}
	if _, ok := ct.BindOrVerify(c, "tok-b", "", 0); ok {
		t.Fatal("a different token was accepted on a bound connection")
	}
	if tok, _ := ct.Get(c); tok != "tok-a" {
		t.Fatalf("binding changed to %q", tok)
	}
}

// 同一条新连接上，携带两个不同有效 token 的请求并发做首次绑定：只有一个 token 绑定成功，
// 其余使用另一个 token 的请求都被拒绝；同一个 token 的请求都通过。
func TestBindOrVerifyConcurrentDifferentTokens(t *testing.T) {
	liveConns(t, nil)
	for round := 0; round < 200; round++ {
		ct := NewConnTracker()
		c := &quic.Conn{}
		const n = 16
		var okA, okB atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			tok := "tok-a"
			if i%2 == 1 {
				tok = "tok-b"
			}
			go func() {
				defer wg.Done()
				<-start
				if _, ok := ct.BindOrVerify(c, tok, "", 0); ok {
					if tok == "tok-a" {
						okA.Add(1)
					} else {
						okB.Add(1)
					}
				}
			}()
		}
		close(start)
		wg.Wait()
		if (okA.Load() == 0) == (okB.Load() == 0) {
			t.Fatalf("round %d: both or neither token bound (a=%d b=%d)", round, okA.Load(), okB.Load())
		}
		winner, _ := ct.Get(c)
		if winner == "tok-a" && okA.Load() != n/2 || winner == "tok-b" && okB.Load() != n/2 {
			t.Fatalf("round %d: winner %s but accepted a=%d b=%d", round, winner, okA.Load(), okB.Load())
		}
	}
}

// 设备数上限仍在首次绑定时执行：同一 uid 超过上限时摘除最早的连接；核对已绑定连接不触发摘除。
func TestBindOrVerifyEvictsOnlyOnFirstBind(t *testing.T) {
	liveConns(t, nil)
	ct := NewConnTracker()
	c1, c2, c3 := &quic.Conn{}, &quic.Conn{}, &quic.Conn{}
	ct.BindOrVerify(c1, "t1", "uid1", 2)
	ct.BindOrVerify(c2, "t2", "uid1", 2)
	ev, ok := ct.BindOrVerify(c3, "t3", "uid1", 2)
	if !ok || len(ev) != 1 || ev[0] != c1 {
		t.Fatalf("expected the oldest connection to be evicted, got ok=%v ev=%v", ok, ev)
	}
	if ev, ok := ct.BindOrVerify(c3, "t3", "uid1", 2); !ok || len(ev) != 0 {
		t.Fatalf("verifying a bound connection evicted something: ok=%v ev=%v", ok, ev)
	}
}
