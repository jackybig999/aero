//go:build android

package tun

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Android routing is VpnService.Builder + protect(fd).
// Same jobs as Win/mac ProtectHostRoute and iOS excludedRoutes:
//   - Builder.establish() default route = catch-all
//   - VpnService.protect(edgeSocketFd) = host exemption
//   - ConnectivityManager.NetworkCallback = Wi-Fi switch refresh
// Do not call `ip route` from the app process.

func SetupRoutes(string, string, string, []string) error { return nil }
func ProtectHostRoute(string) error                      { return nil }
func UnprotectHostRoute(string)                          {}
func RefreshCatchAll(string) error                       { return nil }
func EnsureCatchAll(string) error                        { return nil }

func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	ip, name := firstPhysicalIPv4()
	if ip == nil {
		return "", "", fmt.Errorf("no physical interface (VpnService owns default)")
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

func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	return dialer.DialContext(ctx, network, addr)
}
