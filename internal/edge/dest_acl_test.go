package edge

import (
	"net"
	"net/netip"
	"testing"
)

func TestDestACLBlocksNonPublicDestinations(t *testing.T) {
	blocked := []string{
		// IPv4
		"0.0.0.1", "10.0.0.1", "10.88.0.5", "100.64.0.1", "127.0.0.1",
		"169.254.169.254", "172.16.0.1", "192.0.0.8", "192.0.2.1",
		"192.168.1.1", "198.18.0.1", "198.51.100.7", "203.0.113.7",
		"224.0.0.251", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		// IPv6
		"::", "::1", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1",
		"2001:db8::1", "100::1", "fec0::1",
		// IPv6 内嵌私网 IPv4
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1",
		"2002:c0a8:0101::1", "64:ff9b:1::1",
	}
	for _, s := range blocked {
		if ok, why := destinationBlocked(netip.MustParseAddr(s), nil); !ok {
			t.Errorf("destinationBlocked(%s) = false, want true", s)
		} else if why == "" {
			t.Errorf("destinationBlocked(%s) returned empty reason", s)
		}
	}
}

func TestDestACLAllowsPublicDestinations(t *testing.T) {
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "142.250.72.14", "2606:4700:4700::1111",
		"2001:4860:4860::8888", "64:ff9b::808:808", "2002:0808:0808::1",
	}
	for _, s := range allowed {
		if ok, why := destinationBlocked(netip.MustParseAddr(s), nil); ok {
			t.Errorf("destinationBlocked(%s) = true (%s), want false", s, why)
		}
	}
	if ok, _ := destinationBlocked(netip.Addr{}, nil); !ok {
		t.Error("invalid address must be blocked")
	}
}

func TestDestACLBlocksEdgeOwnAddresses(t *testing.T) {
	own := map[netip.Addr]struct{}{netip.MustParseAddr("8.8.4.4"): {}}
	if ok, why := destinationBlocked(netip.MustParseAddr("8.8.4.4"), own); !ok || why != "edge-local" {
		t.Fatalf("own public address: blocked=%v reason=%q, want true/edge-local", ok, why)
	}
	if ok, _ := destinationBlocked(netip.MustParseAddr("8.8.8.8"), own); ok {
		t.Fatal("other public address must stay allowed")
	}
}

func TestDestACLBlocksOutboundSMTP(t *testing.T) {
	if ok, why := destinationPortBlocked(6, 25); !ok || why != "smtp" {
		t.Fatalf("tcp/25: blocked=%v reason=%q, want true/smtp", ok, why)
	}
	for _, c := range []struct {
		proto uint8
		port  uint16
	}{{6, 443}, {6, 587}, {17, 25}, {17, 53}} {
		if ok, _ := destinationPortBlocked(c.proto, c.port); ok {
			t.Errorf("proto %d port %d must be allowed", c.proto, c.port)
		}
	}
}

// IsBlockedIP 必须与统一 ACL 一致，TCP/UDP 代理路径不得比 CONNECT-IP 宽松。
func TestDestACLIsBlockedIPDelegates(t *testing.T) {
	for _, s := range []string{"224.0.0.1", "0.1.2.3", "240.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe"} {
		if ok, _ := IsBlockedIP(net.ParseIP(s)); !ok {
			t.Errorf("IsBlockedIP(%s) = false, want true", s)
		}
	}
	if ok, _ := IsBlockedIP(net.ParseIP("1.1.1.1")); ok {
		t.Error("IsBlockedIP(1.1.1.1) must be false")
	}
}
