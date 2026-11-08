// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"net"
	"testing"
)

func TestIsLocalOrPrivateIPEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		host string
		ip   net.IP
		want bool
	}{
		{"empty-host-public-ip", "", net.ParseIP("8.8.8.8"), false},
		{"empty-host-private-ip-192", "", net.ParseIP("192.168.1.1"), true},
		{"empty-host-private-ip-10", "", net.ParseIP("10.0.0.1"), true},
		{"empty-host-private-ip-172", "", net.ParseIP("172.16.0.1"), true},
		{"empty-host-nil-ip", "", nil, false},
		{"localhost-string", "localhost", nil, true},
		{"localhost-dot", "localhost.", nil, true},
		{"loopback-ip-string", "127.0.0.1", nil, true},
		{"loopback-net-ip", "", net.ParseIP("127.0.0.1"), true},
		{"cgnat-100-64", "", net.ParseIP("100.64.0.1"), true},
		{"cgnat-100-127", "", net.ParseIP("100.127.255.254"), true},
		{"cgnat-outside-100-63", "", net.ParseIP("100.63.255.255"), false},
		{"cgnat-outside-100-128", "", net.ParseIP("100.128.0.1"), false},
		{"fakeip-range-not-private", "", net.ParseIP("198.18.0.1"), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isLocalOrPrivateIP(c.host, c.ip)
			if got != c.want {
				t.Errorf("isLocalOrPrivateIP(%q, %v) = %v, want %v", c.host, c.ip, got, c.want)
			}
		})
	}
}

func TestChinaIPMatcher_ExportCIDRs(t *testing.T) {
	matcher := NewChinaIPMatcher()
	if matcher == nil {
		t.Fatal("expected non-nil ChinaIPMatcher")
	}
	cidrs := matcher.ExportCIDRs()
	if len(cidrs) == 0 {
		t.Fatal("expected non-empty exported CIDRs")
	}
	t.Logf("Exported %d compact CIDRs from APNIC data", len(cidrs))

	// 验证导出的每一个 CIDR 都能正确被 ParseCIDR 解析
	for i := 0; i < 20; i++ {
		_, ipNet, err := net.ParseCIDR(cidrs[i])
		if err != nil {
			t.Fatalf("invalid exported CIDR %q: %v", cidrs[i], err)
		}
		if !matcher.Contains(ipNet.IP) {
			t.Fatalf("exported CIDR IP %v should be matched by matcher", ipNet.IP)
		}
	}
}
