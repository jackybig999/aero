//go:build darwin && !ios

package tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"
)

// SetupRoutes macOS 路由配置
func SetupRoutes(devName, ipv4, ipv6 string, routes []string) error {
	if ipv4 != "" {
		if err := runMac("ifconfig", devName, "inet", ipv4, ipv4); err != nil {
			log.Printf("[TUN] IPv4 config warning: %v", err)
		}
	}
	if ipv6 != "" {
		if err := runMac("ifconfig", devName, "inet6", ipv6); err != nil {
			log.Printf("[TUN] IPv6 config warning: %v", err)
		}
	}
	if err := runMac("ifconfig", devName, "up"); err != nil {
		return err
	}
	for _, route := range routes {
		if strings.Contains(route, ":") {
			runMac("route", "add", "-inet6", route, "-interface", devName)
		} else {
			runMac("route", "add", route, "-interface", devName)
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
	_ = runMac("route", "-n", "delete", "-host", hostIP)
	if err := runMac("route", "-n", "add", "-host", hostIP, gw); err != nil {
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
	_ = runMac("route", "-n", "delete", "-host", hostIP)
}

func RefreshCatchAll(devName string) error {
	if devName == "" {
		devName = "utun0"
	}
	_ = runMac("route", "delete", "0.0.0.0/1")
	_ = runMac("route", "delete", "128.0.0.0/1")
	if err := runMac("route", "add", "0.0.0.0/1", "-interface", devName); err != nil {
		log.Printf("[TUN] refresh 0.0.0.0/1: %v", err)
	}
	if err := runMac("route", "add", "128.0.0.0/1", "-interface", devName); err != nil {
		log.Printf("[TUN] refresh 128.0.0.0/1: %v", err)
	}
	log.Printf("[TUN] refreshed catch-all on %s", devName)
	return nil
}

func EnsureCatchAll(devName string) error {
	if devName == "" {
		devName = "utun0"
	}
	_ = runMac("route", "add", "0.0.0.0/1", "-interface", devName)
	_ = runMac("route", "add", "128.0.0.0/1", "-interface", devName)
	log.Printf("[TUN] ensure catch-all on %s (no bounce)", devName)
	return nil
}

func physicalDefaultName() (gw, iface string, err error) {
	out, e := exec.Command("netstat", "-rn", "-f", "inet").CombinedOutput()
	if e == nil {
		gw, iface = ParseDarwinNetstatDefaults(string(out))
		if gw != "" {
			return gw, iface, nil
		}
	}
	out, e = exec.Command("route", "-n", "get", "default").CombinedOutput()
	if e != nil {
		return "", "", e
	}
	gw, iface = ParseDarwinRouteGet(string(out))
	if gw == "" {
		return "", "", fmt.Errorf("no physical default gateway")
	}
	return gw, iface, nil
}

func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	gw, iface, err := physicalDefaultName()
	if err != nil {
		return "", "", err
	}
	return gw, ifaceIndexByName(iface), nil
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
	_ = runMac("route", "delete", "0.0.0.0/1")
	_ = runMac("route", "delete", "128.0.0.0/1")
	log.Printf("[TUN] catch-all routes removed from %s", devName)
}

func SetupDNS(servers []string) {
	dns := "8.8.8.8"
	if len(servers) > 0 && servers[0] != "" {
		dns = servers[0]
	}
	log.Printf("[TUN] DNS %s (macOS physical DNS unchanged; utun has no scutil rewrite)", dns)
}

func TeardownDNS() {}

func runMac(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	return dialer.DialContext(ctx, network, addr)
}
