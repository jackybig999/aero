package edge

import (
	"net/netip"
	"testing"
	"time"
)

// 同一 token 断开后重连拿回原地址；租约期内地址不分给其他会话；过期后释放。
func TestIPPoolLeaseStickyPerToken(t *testing.T) {
	pool, err := NewIPPool("10.88.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	pool.now = func() time.Time { return now }

	a, err := pool.AllocateFor("tok_a")
	if err != nil {
		t.Fatal(err)
	}
	pool.ReleaseFor("tok_a", a)

	// 租约期内，即使顺序分配正好轮到 a，其他（无 token 的顺序）分配也拿不到它
	pool.nextHost = hostOf(a)
	if other, err := pool.Allocate(); err != nil || other == a {
		t.Fatalf("leased address %s handed to another token (got %s, err %v)", a, other, err)
	}

	again, err := pool.AllocateFor("tok_a")
	if err != nil || again != a {
		t.Fatalf("reconnect got %s (err %v), want the same address %s", again, err, a)
	}
	pool.ReleaseFor("tok_a", again)

	now = now.Add(ipLeaseTTL + time.Second)
	pool.nextHost = hostOf(a) // 让顺序分配正好落在 a 上
	other, err := pool.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if other != a {
		t.Fatalf("expired lease: got %s, want %s to be reusable", other, a)
	}
}

// 同一 token 的第二个并发会话（另一台设备）拿到不同地址。
func TestIPPoolLeaseConcurrentSessionsSameToken(t *testing.T) {
	pool, err := NewIPPool("10.88.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := pool.AllocateFor("tok_a")
	b, err := pool.AllocateFor("tok_a")
	if err != nil || a == b {
		t.Fatalf("second concurrent session got %s (err %v), must differ from %s", b, err, a)
	}
}

// edge 重启后租约丢失：同一 token 在新的地址池上仍应拿回同一地址（按 token 哈希定位）。
func TestIPPoolLeaseSameAddressAfterRestart(t *testing.T) {
	before, _ := NewIPPool("10.88.0.0/16")
	// 先让顺序指针前进，确保结果不是“碰巧都从头分配”
	for i := 0; i < 37; i++ {
		_, _ = before.Allocate()
	}
	a, err := before.AllocateFor("tok_restart")
	if err != nil {
		t.Fatal(err)
	}

	after, _ := NewIPPool("10.88.0.0/16") // 模拟 edge 重启：全新的池，没有租约
	b, err := after.AllocateFor("tok_restart")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("after restart token got %s, want %s", b, a)
	}
}

// hostOf 返回 10.88.0.0/16 内地址的主机号。
func hostOf(p netip.Prefix) uint32 {
	a := p.Addr().As4()
	return uint32(a[2])<<8 | uint32(a[3])
}
