//go:build windows

package client

import (
	"net"
	"syscall"
	"testing"
)

// 真实系统上（CI 的 Windows 机器）经 IP Helper API 读取路由表并选出物理默认网关；与系统语言无关。
func TestWindowsRoutesAndPhysicalGatewayFromAPI(t *testing.T) {
	routes, err := readIPv4Routes()
	if err != nil {
		t.Fatalf("readIPv4Routes: %v", err)
	}
	hasDefault := false
	for _, r := range routes {
		if r.Dest == defRoute {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Skip("no IPv4 default route on this machine")
	}
	invalidateGatewayCache()
	gw, idx, err := PhysicalDefaultGateway()
	if err != nil || net.ParseIP(gw) == nil || idx == "" || idx == "0" {
		t.Fatalf("PhysicalDefaultGateway = %q %q %v", gw, idx, err)
	}
	if _, name, err := DetectThirdPartyTUN(); err != nil {
		t.Fatalf("DetectThirdPartyTUN: %v (%s)", err, name)
	}
}

// IPv4 套接字用 IPPROTO_IP + 大端索引；IPv6 套接字必须用 IPPROTO_IPV6 + 主机字节序（小端）索引。
func TestUnicastIfSockopt(t *testing.T) {
	const idx = 0x01020304
	cases := []struct {
		network string
		level   int
		val     [4]byte
	}{
		{"udp4", syscall.IPPROTO_IP, [4]byte{1, 2, 3, 4}},
		{"tcp4", syscall.IPPROTO_IP, [4]byte{1, 2, 3, 4}},
		{"udp6", syscall.IPPROTO_IPV6, [4]byte{4, 3, 2, 1}},
		{"tcp6", syscall.IPPROTO_IPV6, [4]byte{4, 3, 2, 1}},
	}
	for _, c := range cases {
		level, opt, val := unicastIfSockopt(c.network, idx)
		if level != c.level || opt != 31 || val != c.val {
			t.Errorf("unicastIfSockopt(%q) = (%d, %d, %v), want (%d, 31, %v)", c.network, level, opt, val, c.level, c.val)
		}
	}
}
