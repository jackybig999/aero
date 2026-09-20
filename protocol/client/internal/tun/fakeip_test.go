package tun_test

import (
	"fmt"
	"net"
	"runtime"
	"testing"

	"github.com/aero-protocol/aero-ech/internal/tun"
)

func TestFakeIPTable_LRUEviction(t *testing.T) {
	tbl := tun.NewFakeIPTable("198.18.0.0/15", 5)

	var ips []net.IP
	for i := 1; i <= 5; i++ {
		host := fmt.Sprintf("host%d.example.com", i)
		ip := tbl.Allocate(host)
		ips = append(ips, ip)
	}

	if tbl.Size() != 5 {
		t.Fatalf("expected size 5, got %d", tbl.Size())
	}

	// 访问 host1，刷新其为 MRU
	resolved1, ok := tbl.Lookup(ips[0])
	if !ok || resolved1 != "host1.example.com" {
		t.Fatalf("lookup host1 failed")
	}

	// 此时 LRU 最老条目为 host2（因为 host1 被访问了）
	// 分配第 6 个域名，应触发 LRU 淘汰 host2
	ip6 := tbl.Allocate("host6.example.com")
	if tbl.Size() != 5 {
		t.Fatalf("expected size 5 after eviction, got %d", tbl.Size())
	}

	// 验证 host2 已被驱逐
	if _, ok := tbl.Lookup(ips[1]); ok {
		t.Fatalf("expected host2 to be evicted, but it was found")
	}

	// 验证 host1 与 host6 都在
	if _, ok := tbl.Lookup(ips[0]); !ok {
		t.Fatalf("expected host1 to be preserved")
	}
	if host6, ok := tbl.Lookup(ip6); !ok || host6 != "host6.example.com" {
		t.Fatalf("expected host6 to be preserved")
	}
}

func TestFakeIPTable_100kMemoryBound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 100k memory test in short mode")
	}

	tbl := tun.NewFakeIPTable("198.18.0.0/15", tun.DefaultMaxFakeIPSlots)

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// 模拟 100,000 次不同域名的并发/密集解析
	for i := 0; i < 100000; i++ {
		host := fmt.Sprintf("cluster-%d.subdomain-%d.ultra-scale.net", i%70000, i)
		ip := tbl.Allocate(host)
		if i%10 == 0 {
			_, _ = tbl.Lookup(ip)
		}
	}

	if tbl.Size() > tun.DefaultMaxFakeIPSlots {
		t.Fatalf("table size exceeded maxSlots: %d > %d", tbl.Size(), tun.DefaultMaxFakeIPSlots)
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocatedBytes := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	allocatedMB := float64(allocatedBytes) / (1024 * 1024)
	t.Logf("100k queries: table size = %d, HeapAlloc diff = %.2f MB", tbl.Size(), allocatedMB)

	// 铁律 L5 验证：FakeDNS 内存极限锁定在 ~8MB 范围，杜绝无界增长
	if allocatedMB > 12.0 {
		t.Fatalf("FakeDNS memory consumption too high: %.2f MB > 12 MB limit", allocatedMB)
	}
}
