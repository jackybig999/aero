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
