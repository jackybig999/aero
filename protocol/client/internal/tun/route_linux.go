//go:build linux && !android

package tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func SetupRoutes(devName, ipv4, ipv6 string, routes []string) error {
	if err := run("ip", "link", "set", devName, "up"); err != nil {
		return err
	}
	if ipv4 != "" {
		if err := run("ip", "addr", "add", ipv4, "dev", devName); err != nil {
			log.Printf("[TUN] IPv4 addr warning: %v", err)
		}
	}
	if ipv6 != "" {
		if err := run("ip", "addr", "add", ipv6, "dev", devName); err != nil {
			log.Printf("[TUN] IPv6 addr warning: %v", err)
		}
	}
	for _, route := range routes {
		if strings.Contains(route, ":") {
			run("ip", "-6", "route", "replace", route, "dev", devName)
		} else {
			run("ip", "route", "replace", route, "dev", devName)
		}
	}
	log.Printf("[TUN] Routes configured on %s", devName)
	return nil
}

func ProtectHostRoute(hostIP string) error {
	ip := net.ParseIP(hostIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	gw, iface, err := PhysicalDefaultGateway()
	if err != nil || gw == "" {
		log.Printf("[TUN] protect %s: no default gw (%v)", hostIP, err)
		return err
	}
	args := []string{"route", "replace", hostIP + "/32", "via", gw}
	if iface != "" && !isAllDigits(iface) {
		args = append(args, "dev", iface)
	}
	if err := run("ip", args...); err != nil {
		log.Printf("[TUN] protect route %s via %s: %v", hostIP, gw, err)
		return err
	}
	log.Printf("[TUN] protected edge host route %s via %s if=%s", hostIP, gw, iface)
	return nil
}

func UnprotectHostRoute(hostIP string) {
	if hostIP == "" {
		return
	}
	_ = run("ip", "route", "del", hostIP+"/32")
}

func RefreshCatchAll(devName string) error {
	if devName == "" {
		devName = "aero0"
	}
	_ = run("ip", "route", "replace", "0.0.0.0/1", "dev", devName)
	_ = run("ip", "route", "replace", "128.0.0.0/1", "dev", devName)
	log.Printf("[TUN] refreshed catch-all on %s", devName)
	return nil
}

func EnsureCatchAll(devName string) error { return RefreshCatchAll(devName) }

func physicalDefaultName() (gw, iface string, err error) {
	out, e := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if e != nil {
		return "", "", e
	}
	gw, iface = ParseLinuxDefaults(string(out))
	if gw == "" {
		return "", "", fmt.Errorf("no physical default gateway")
	}
	return gw, iface, nil
}

func InvalidatePhysicalDefault() {}

func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	gw, iface, err := physicalDefaultName()
	if err != nil {
		return "", "", err
	}
	idx := ifaceIndexByName(iface)
	if idx == "" {
		idx = iface
	}
	return gw, idx, nil
}

func PhysicalIfaceIPv4() net.IP {
	_, iface, err := physicalDefaultName()
	if err == nil {
		if ip := ifaceIPv4ByName(iface); ip != nil {
			return ip
		}
	}
	ip, _ := firstPhysicalIPv4()
	return ip
}

func TeardownRoutes(devName string) {
	_ = run("ip", "route", "del", "0.0.0.0/1")
	_ = run("ip", "route", "del", "128.0.0.0/1")
	log.Printf("[TUN] catch-all routes removed from %s", devName)
}

func SetupDNS(servers []string) {
	dns := "8.8.8.8"
	if len(servers) > 0 && servers[0] != "" {
		dns = servers[0]
	}
	log.Printf("[TUN] DNS %s (Linux physical resolv.conf unchanged)", dns)
}

func TeardownDNS() {}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	_, ifaceName, err := PhysicalDefaultGateway()
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	if err == nil && ifaceName != "" {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var opErr error
			_ = c.Control(func(fd uintptr) {
				// SO_BINDTODEVICE = 25 (Linux socket option to bind outbound socket to physical network device)
				opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName)
			})
			return opErr
		}
	}
	return dialer.DialContext(ctx, network, addr)
}
