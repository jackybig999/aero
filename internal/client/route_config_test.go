package client

import (
	"net/netip"
	"testing"
)

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
	if tunPool != netip.MustParsePrefix("10.88.0.0/16") || tunGateway(netip.PrefixFrom(netip.MustParseAddr("10.88.255.254"), tunPool.Bits())) != netip.MustParseAddr("10.88.0.1") {
		t.Fatalf("tunPool %v: gateway 10.88.0.1 must be inside the pool for every assigned address", tunPool)
	}
}
