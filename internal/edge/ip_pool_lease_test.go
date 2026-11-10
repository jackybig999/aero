package edge

import (
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

	// 租约期内，即使顺序分配正好轮到 a，其他会话也拿不到它
	pool.nextHost = uint32(a.Addr().As4()[3])
	if other, err := pool.AllocateFor("tok_other"); err != nil || other == a {
		t.Fatalf("leased address %s handed to another token (got %s, err %v)", a, other, err)
	}

	again, err := pool.AllocateFor("tok_a")
	if err != nil || again != a {
		t.Fatalf("reconnect got %s (err %v), want the same address %s", again, err, a)
	}
	pool.ReleaseFor("tok_a", again)

	now = now.Add(ipLeaseTTL + time.Second)
	pool.nextHost = uint32(a.Addr().As4()[3]) // 让顺序分配正好落在 a 上
	other, err := pool.AllocateFor("tok_later")
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
