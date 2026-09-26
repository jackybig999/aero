//go:build ios

package tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

// iOS routing is owned by NEPacketTunnelNetworkSettings.
// The Swift provider MUST set ipv4.excludedRoutes to the edge /32
// (same job as ProtectHostRoute on Win/mac) and refresh it on NWPathMonitor.

func SetupRoutes(string, string, string, []string) error { return nil }

func ProtectHostRoute(string) error { return nil }
func UnprotectHostRoute(string)     {}
func RefreshCatchAll(string) error  { return nil }
func EnsureCatchAll(string) error   { return nil }

func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	ip, name := firstPhysicalIPv4()
	if ip == nil {
		return "", "", fmt.Errorf("no physical interface (Network Extension owns default)")
	}
	return ip.String(), name, nil
}

func PhysicalIfaceIPv4() net.IP {
	ip, _ := firstPhysicalIPv4()
	return ip
}

func TeardownRoutes(string) {}
func SetupDNS([]string)     {}
func TeardownDNS()          {}

func init() {
	log.Printf("[TUN] iOS: host protect is NE excludedRoutes, not userspace route")
}

func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	return dialer.DialContext(ctx, network, addr)
}
