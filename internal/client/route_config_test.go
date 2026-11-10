package client

import (
	"net/netip"
	"testing"
)

func TestRouteConfig(t *testing.T) {
	withoutIPv6, err := NewRouteConfig("10.88.0.2/24", nil, 1224)
	if err != nil {
		t.Fatalf("unexpected IPv4-only error: %v", err)
	}
	if withoutIPv6.EnableIPv6 || !withoutIPv6.EnableIPv6Blackhole || withoutIPv6.InitialMTU != 1224 {
		t.Fatalf("unexpected IPv4-only config: %+v", withoutIPv6)
	}

	global := netip.MustParsePrefix("2001:db8:1234:5678::/64")
	withIPv6, err := NewRouteConfig("10.88.0.2/24", &global, 1224)
	if err != nil {
		t.Fatalf("unexpected dual-stack error: %v", err)
	}
	if !withIPv6.EnableIPv6 || withIPv6.EnableIPv6Blackhole || withIPv6.IPv6 != global {
		t.Fatalf("unexpected dual-stack config: %+v", withIPv6)
	}

	ula := netip.MustParsePrefix("fd88::/64")
	if _, err := NewRouteConfig("10.88.0.2/24", &ula, 1224); err == nil {
		t.Fatal("expected ULA IPv6 prefix rejection")
	}
}

// 客户端对隧道地址的判断与 edge 地址池 10.88.0.0/16 一致：edge 按 token 哈希分配，
// 地址可在整个 /16 内，不能再假设 10.88.0.2 或 /24。
func TestTunPoolMatchesEdgePool(t *testing.T) {
	for _, ip := range []string{"10.88.0.2", "10.88.5.7", "10.88.255.254"} {
		if !isAeroTunAddr(ip) {
			t.Errorf("isAeroTunAddr(%s) = false, want true", ip)
		}
	}
	for _, ip := range []string{"10.89.0.2", "192.168.1.2", "", "not-an-ip"} {
		if isAeroTunAddr(ip) {
			t.Errorf("isAeroTunAddr(%q) = true, want false", ip)
		}
	}
	if got := tunPoolMask(); got != "255.255.0.0" {
		t.Fatalf("tunPoolMask() = %s, want 255.255.0.0 (gateway 10.88.0.1 must be on-link for every pool address)", got)
	}
}
