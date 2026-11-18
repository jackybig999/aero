//go:build windows

package client

import (
	"net"
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
