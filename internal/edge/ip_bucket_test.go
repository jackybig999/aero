// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"fmt"
	"testing"
)

func TestIPBucketKey(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.7", "203.0.113.7"}, // v4-mapped 与 IPv4 是同一主机
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"fe80::1%eth0", "fe80::/64"}, // 去掉 zone
		{"not-an-ip", "not-an-ip"},    // 解析失败原样返回
		{"", ""},
	} {
		if got := ipBucketKey(c.in); got != c.want {
			t.Errorf("ipBucketKey(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

// 同一 /64 内换地址不能绕过封禁：失败次数合并计算，封禁对整个 /64 生效；其他 /64 不受影响。
func TestAuthJailAggregatesIPv6Prefix(t *testing.T) {
	j := NewAuthFailureJail()
	t.Cleanup(j.Close)
	for i := 0; i < 5; i++ {
		j.RecordFailure(fmt.Sprintf("2001:db8:1:2::%x", i+1)) // 每次换一个地址
	}
	if !j.IsBanned("2001:db8:1:2::ffff") {
		t.Fatal("同一 /64 内换地址的 5 次失败应触发封禁（对整个 /64）")
	}
	if j.IsBanned("2001:db8:1:3::1") {
		t.Fatal("其他 /64 不应受影响")
	}
	// IPv4 仍按单个地址计数。
	for i := 0; i < 4; i++ {
		j.RecordFailure("198.51.100.1")
	}
	if j.IsBanned("198.51.100.1") || j.IsBanned("198.51.100.2") {
		t.Fatal("IPv4 4 次失败不应封禁，也不应影响相邻地址")
	}
}

// 填表攻击：一个 /64 内的海量地址只占一条记录，不会把 1 万条的表填满而使其他来源的封禁失效。
func TestAuthJailIPv6FloodDoesNotFillTable(t *testing.T) {
	j := NewAuthFailureJail()
	t.Cleanup(j.Close)
	for i := 0; i < maxJailEntries+500; i++ {
		j.RecordFailure(fmt.Sprintf("2001:db8:ffff:ffff::%x:%x", i>>16, i&0xffff))
	}
	j.mu.RLock()
	n := len(j.records)
	j.mu.RUnlock()
	if n != 1 {
		t.Fatalf("同一 /64 的 %d 个地址应只占 1 条记录，实际 %d", maxJailEntries+500, n)
	}
	// 表里还有空间：其他来源的失败仍被记录并能被封禁。
	for i := 0; i < 5; i++ {
		j.RecordFailure("203.0.113.9")
	}
	if !j.IsBanned("203.0.113.9") {
		t.Fatal("洪泛之后其他来源仍应能被封禁")
	}
}

// 连接限速同样按 /64 共用一个桶。
func TestRateLimiterSharesIPv6Prefix(t *testing.T) {
	rl := NewRateLimiter(3) // 每秒 3 个
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(fmt.Sprintf("2001:db8:5:5::%x", i+1)) { // 同一 /64 内换地址
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("同一 /64 共用一个桶，应放行 3 个，实际 %d", allowed)
	}
	if !rl.Allow("2001:db8:5:6::1") {
		t.Fatal("其他 /64 有自己的桶")
	}
}
