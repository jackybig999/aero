//go:build windows

package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// dnsTouched unused: we never rewrite physical NIC DNS (that blackholed the PC).

// SetupRoutes assigns IP and catch-all routes bound to the TUN *interface index*.
// Next-hop-only routes on Windows often never deliver packets into wintun.
func SetupRoutes(devName, ipv4, ipv6 string, routes []string) error {
	tunIP := "10.88.0.2"
	if ipv4 != "" {
		parts := strings.Split(ipv4, "/")
		tunIP = parts[0]
		if len(parts) == 2 {
			mask := cidrToMask(parts[1])
			_ = runCmd("netsh", "interface", "ip", "set", "address",
				"name="+devName, "source=static", "addr="+tunIP, "mask="+mask, "gateway=none")
			_ = runCmd("netsh", "interface", "ip", "set", "address",
				devName, "static", tunIP, mask)
		}
	}
	_ = runCmd("netsh", "interface", "set", "interface", "name="+devName, "admin=ENABLED")
	time.Sleep(400 * time.Millisecond)

	idx := interfaceIndex(devName)
	if idx == "" {
		log.Printf("[TUN] WARN no ifIndex for %s — packets may miss wintun", devName)
	}

	// 1. 设置 MTU 为 1380，规避封装膨胀并将 TCP MSS 自动钳制为 1340
	_ = runCmd("netsh", "interface", "ipv4", "set", "subinterface", devName, "mtu=1380", "store=active")

	// 2. 彻底封堵 IPv6 泄漏：为 TUN 分配 IPv6 地址并下发 catch-all 捕获路由
	tunIPv6 := "fd88::2"
	if ipv6 != "" {
		p := strings.Split(ipv6, "/")
		if len(p) > 0 && p[0] != "" {
			tunIPv6 = p[0]
		}
	}
	_ = runCmd("netsh", "interface", "ipv6", "set", "interface", devName, "admin=ENABLED")
	_ = runCmd("netsh", "interface", "ipv6", "set", "subinterface", devName, "mtu=1380", "store=active")
	_ = runCmd("netsh", "interface", "ipv6", "add", "address", devName, tunIPv6+"/64")

	_ = runCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_ = runCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	addSplitDefault := func(dst, mask string) {
		args := []string{"add", dst, "mask", mask, tunIP, "metric", "1"}
		if idx != "" {
			args = append(args, "if", idx)
		}
		if err := runCmd("route", args...); err != nil {
			log.Printf("[TUN] route %s: %v", dst, err)
		}
	}
	addSplitDefault("0.0.0.0", "128.0.0.0")
	addSplitDefault("128.0.0.0", "128.0.0.0")

	// 注入 IPv6 全局捕获路由，强制所有 IPv6 流量进入 TUN，杜绝物理网卡裸连泄露
	_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "::/1", devName)
	_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "8000::/1", devName)
	_ = runCmd("netsh", "interface", "ipv6", "add", "route", "::/1", devName, "metric=1", "store=active")
	_ = runCmd("netsh", "interface", "ipv6", "add", "route", "8000::/1", devName, "metric=1", "store=active")

	log.Printf("[TUN] Routes on %s via %s (IPv6 %s) if=%s (MTU=1380)", devName, tunIP, tunIPv6, idx)
	return nil
}

func interfaceIndex(name string) string {
	show := exec.Command("netsh", "interface", "ipv4", "show", "interfaces")
	show.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := show.Output()
	if err != nil {
		return ""
	}
	want := strings.ToLower(name)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if strings.ToLower(fields[len(fields)-1]) == want {
			return fields[0]
		}
	}
	return ""
}

// ProtectHostRoute forces traffic to hostIP via the physical default gateway,
// so Edge tunnel does not re-enter TUN (classic VPN exclusion).
func ProtectHostRoute(hostIP string) error {
	ip := net.ParseIP(hostIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	gw, ifIndex, err := defaultGateway()
	if err != nil || gw == "" {
		log.Printf("[TUN] protect %s: no default gw (%v)", hostIP, err)
		return err
	}
	_ = runCmd("route", "delete", hostIP)
	args := []string{"add", hostIP, "mask", "255.255.255.255", gw, "metric", "1"}
	if ifIndex != "" {
		args = append(args, "if", ifIndex)
	}
	if err := runCmd("route", args...); err != nil {
		// Retry without IF: a stale/wrong index is why switch-network drops TUN.
		args = []string{"add", hostIP, "mask", "255.255.255.255", gw, "metric", "1"}
		if err2 := runCmd("route", args...); err2 != nil {
			log.Printf("[TUN] protect route %s via %s: %v", hostIP, gw, err2)
			return err2
		}
	}
	log.Printf("[TUN] protected edge host route %s via %s if=%s", hostIP, gw, ifIndex)
	return nil
}

// RefreshCatchAll re-enables aero0 and reinstalls split-default routes.
// Windows drops or overrides these when the physical NIC changes.
func RefreshCatchAll(devName string) error {
	if devName == "" {
		devName = "aero0"
	}
	_ = runCmd("netsh", "interface", "set", "interface", "name="+devName, "admin=ENABLED")
	time.Sleep(200 * time.Millisecond)
	idx := interfaceIndex(devName)
	_ = runCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_ = runCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	add := func(dst, mask string) {
		args := []string{"add", dst, "mask", mask, "10.88.0.2", "metric", "1"}
		if idx != "" {
			args = append(args, "if", idx)
		}
		if err := runCmd("route", args...); err != nil {
			log.Printf("[TUN] refresh route %s: %v", dst, err)
		}
	}
	add("0.0.0.0", "128.0.0.0")
	add("128.0.0.0", "128.0.0.0")
	log.Printf("[TUN] refreshed catch-all on %s if=%s", devName, idx)
	return nil
}

func routeAlreadyExists(err error) bool {
	if err == nil {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already") || strings.Contains(s, "已存在")
}

// EnsureCatchAll adds split-default routes if missing. Requires aero0 ifIndex.
// Wi-Fi switch must not enable the adapter or delete /1 (that drops NLA and can blackhole).
func EnsureCatchAll(devName string) error {
	if devName == "" {
		devName = "aero0"
	}
	idx := interfaceIndex(devName)
	if idx == "" {
		log.Printf("[TUN] ensure catch-all skipped: no ifIndex for %s", devName)
		return fmt.Errorf("no ifIndex for %s", devName)
	}
	add := func(dst, mask string) {
		args := []string{"add", dst, "mask", mask, "10.88.0.2", "metric", "1", "if", idx}
		if err := runCmd("route", args...); err != nil && !routeAlreadyExists(err) {
			log.Printf("[TUN] ensure route %s if=%s: %v", dst, idx, err)
		}
	}
	add("0.0.0.0", "128.0.0.0")
	add("128.0.0.0", "128.0.0.0")
	log.Printf("[TUN] ensure catch-all on %s if=%s (no bounce)", devName, idx)
	return nil
}

// UnprotectHostRoute removes host route for edge IP.
func UnprotectHostRoute(hostIP string) {
	if hostIP == "" {
		return
	}
	_ = runCmd("route", "delete", hostIP)
}

// PhysicalDefaultGateway is the current Wi-Fi/Ethernet gateway, never 10.88.
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	return defaultGateway()
}

type ipv4Default struct {
	gw      string
	ifaceIP net.IP
	metric  int
}

// parseIPv4Defaults reads `route print -4` 0.0.0.0/0 lines, skipping TUN hops.
func parseIPv4Defaults(routePrint string) []ipv4Default {
	var out []ipv4Default
	for _, line := range strings.Split(routePrint, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		cand := fields[2]
		if net.ParseIP(cand) == nil || IsTUNIPv4(cand) {
			continue
		}
		ip := net.ParseIP(fields[3])
		if ip == nil || ip.To4() == nil || IsTUNIPv4(ip.String()) {
			continue
		}
		metric := 9999
		if len(fields) >= 5 {
			if n, err := strconv.Atoi(fields[4]); err == nil {
				metric = n
			}
		}
		out = append(out, ipv4Default{gw: cand, ifaceIP: ip.To4(), metric: metric})
	}
	return out
}

func defaultGateway() (gw, ifIndex string, err error) {
	d, idx, err := livePhysicalDefault()
	if err != nil {
		return "", "", err
	}
	return d.gw, idx, nil
}

var (
	physDefMu       sync.Mutex
	lastPhysDef     ipv4Default
	lastPhysDefIdx  string
	lastPhysDefTime time.Time
)

// InvalidatePhysicalDefault 强制清除物理默认网卡缓存，确保 Wi-Fi 漫游后立即感知新网关
func InvalidatePhysicalDefault() {
	physDefMu.Lock()
	lastPhysDef = ipv4Default{}
	lastPhysDefIdx = ""
	lastPhysDefTime = time.Time{}
	physDefMu.Unlock()
}

func livePhysicalDefault() (ipv4Default, string, error) {
	physDefMu.Lock()
	if time.Since(lastPhysDefTime) < 1*time.Second && lastPhysDef.gw != "" {
		d, idx := lastPhysDef, lastPhysDefIdx
		physDefMu.Unlock()
		return d, idx, nil
	}
	physDefMu.Unlock()

	prt := exec.Command("route", "print", "-4")
	prt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, e := prt.CombinedOutput()
	if e != nil {
		return ipv4Default{}, "", e
	}
	var best ipv4Default
	bestIdx := ""
	found := false
	for _, d := range parseIPv4Defaults(string(out)) {
		idx := liveIfIndexForIPv4(d.ifaceIP)
		if idx == "" {
			continue
		}
		if !found || d.metric < best.metric {
			best = d
			bestIdx = idx
			found = true
		}
	}
	if !found {
		return ipv4Default{}, "", fmt.Errorf("no physical default gateway")
	}

	physDefMu.Lock()
	lastPhysDef = best
	lastPhysDefIdx = bestIdx
	lastPhysDefTime = time.Now()
	physDefMu.Unlock()

	return best, bestIdx, nil
}

func liveIfIndexForIPv4(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if IsTUNName(ifi.Name) {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			if ipn.IP.To4().Equal(ip) {
				return strconv.Itoa(ifi.Index)
			}
		}
	}
	return ""
}

func ifIndexForIPv4(ip net.IP) string {
	return liveIfIndexForIPv4(ip)
}

// PhysicalIfaceIPv4 is the IPv4 of the NIC that currently owns 0.0.0.0/0.
func PhysicalIfaceIPv4() net.IP {
	d, _, err := livePhysicalDefault()
	if err != nil {
		return nil
	}
	return d.ifaceIP
}

// TeardownRoutes 清理 catch-all TUN routes
func TeardownRoutes(devName string) {
	_ = runCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_ = runCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	if devName != "" {
		_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", devName)
		_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", devName)
		_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "::/1", devName)
		_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "8000::/1", devName)
	}
	log.Printf("[TUN] Routes removed for %s", devName)
}

// SetupDNS only touches the TUN adapter. Never rewrite WLAN/Ethernet DNS —
// a crash then leaves the whole PC unable to resolve anything.
func SetupDNS(servers []string) {
	dns := "8.8.8.8"
	if len(servers) > 0 && servers[0] != "" {
		dns = servers[0]
	}
	_ = runCmd("netsh", "interface", "ip", "set", "dns", "name=aero0", "static", dns, "primary")
	log.Printf("[TUN] aero0 DNS %s (physical NIC DNS unchanged)", dns)
}

func TeardownDNS() {
	_ = runCmd("netsh", "interface", "ip", "set", "dns", "name=aero0", "dhcp")
	log.Printf("[TUN] aero0 DNS cleared")
}

func runCmd(name string, args ...string) error {
	clean := make([]string, 0, len(args))
	for _, a := range args {
		if a != "" {
			clean = append(clean, a)
		}
	}
	cmd := exec.Command(name, clean...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, clean, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func cidrToMask(cidr string) string {
	bits := 0
	fmt.Sscanf(cidr, "%d", &bits)
	mask := [4]byte{}
	for i := 0; i < bits; i++ {
		mask[i/8] |= 1 << (7 - i%8)
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

// DialPhysicalDirect 绑定 Windows 物理网络适配器（IP_UNICAST_IF），100% 绕过 TUN 路由表直连
func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	_, idxStr, err := PhysicalDefaultGateway()
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	if err == nil && idxStr != "" {
		if idx, err := strconv.Atoi(idxStr); err == nil && idx > 0 {
			dialer.Control = func(netw, address string, c syscall.RawConn) error {
				var opErr error
				_ = c.Control(func(fd uintptr) {
					var buf [4]byte
					binary.BigEndian.PutUint32(buf[:], uint32(idx))
					// ws2ipdef.h: IP_UNICAST_IF = 31 (强制覆盖路由表从指定物理网卡发包)
					opErr = syscall.Setsockopt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, (*byte)(unsafe.Pointer(&buf[0])), 4)
				})
				return opErr
			}
		}
	}
	return dialer.DialContext(ctx, network, addr)
}

// ListenPhysicalPacket 绑定 Windows 物理网络适配器（IP_UNICAST_IF），100% 绕过 TUN 路由表发包
func ListenPhysicalPacket(ctx context.Context, network string) (net.PacketConn, error) {
	_, idxStr, err := PhysicalDefaultGateway()
	var lc net.ListenConfig
	if err == nil && idxStr != "" {
		if idx, err := strconv.Atoi(idxStr); err == nil && idx > 0 {
			lc.Control = func(netw, address string, c syscall.RawConn) error {
				var opErr error
				_ = c.Control(func(fd uintptr) {
					var buf [4]byte
					binary.BigEndian.PutUint32(buf[:], uint32(idx))
					opErr = syscall.Setsockopt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, (*byte)(unsafe.Pointer(&buf[0])), 4)
				})
				return opErr
			}
		}
	}
	return lc.ListenPacket(ctx, network, ":0")
}
