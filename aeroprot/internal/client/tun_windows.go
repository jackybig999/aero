//go:build windows

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

//go:embed wintun.dll
var embeddedWintunDLL []byte

func ensureWintunDLL() error {
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		target := filepath.Join(exeDir, "wintun.dll")
		if _, err := os.Stat(target); err == nil {
			return nil
		}
		if len(embeddedWintunDLL) > 0 {
			if werr := os.WriteFile(target, embeddedWintunDLL, 0755); werr == nil {
				log.Printf("[TUN] auto-extracted wintun.dll to %s", target)
				return nil
			}
		}
	}

	sys32 := filepath.Join(os.Getenv("SystemRoot"), "System32", "wintun.dll")
	if _, err := os.Stat(sys32); err == nil {
		return nil
	}

	if _, err := os.Stat("wintun.dll"); err == nil {
		return nil
	}
	if len(embeddedWintunDLL) > 0 {
		if err := os.WriteFile("wintun.dll", embeddedWintunDLL, 0755); err == nil {
			log.Printf("[TUN] auto-extracted wintun.dll to current directory")
			return nil
		}
	}
	return nil
}

var (
	guardOnce sync.Once
	guardMu   sync.Mutex
	guardPID  int
)

func startCrashGuard() {
	guardOnce.Do(startCrashGuardOnce)
}

func startCrashGuardOnce() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(dir, "aeroprot-guard.exe"),
		filepath.Join(dir, "aerosys-guard-windows-amd64.exe"),
		filepath.Join(dir, "guard.exe"),
		filepath.Join(dir, "aero-guard.exe"),
	}
	var guardPath string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			guardPath = c
			break
		}
	}
	if guardPath == "" {
		return
	}
	cmd := exec.Command(guardPath, "-pid", strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		CreationFlags: windows.DETACHED_PROCESS |
			windows.CREATE_NEW_PROCESS_GROUP |
			windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[GUARD] failed to start watchdog: %v", err)
		return
	}
	guardMu.Lock()
	guardPID = cmd.Process.Pid
	guardMu.Unlock()
	log.Printf("[GUARD] watchdog started (%s, pid=%d) monitoring client pid=%d", filepath.Base(guardPath), cmd.Process.Pid, os.Getpid())
	_ = cmd.Process.Release()
}

func stopCrashGuard() {
	guardMu.Lock()
	pid := guardPID
	guardPID = 0
	guardMu.Unlock()
	if pid <= 0 {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Kill()
	log.Printf("[GUARD] stopped watchdog pid=%d", pid)
}

const errorNoMoreItems = syscall.Errno(259)

type windowsDevice struct {
	name      string
	mtu       int
	adapter   *wintun.Adapter
	session   wintun.Session
	sessionOK atomic.Bool
	closed    atomic.Bool
	writeMu   sync.Mutex
}

// OpenTunDevice 打开或创建 Windows Wintun 虚拟网卡（初始 MTU 1360）
func OpenTunDevice(name string, mtu int) (TunDevice, error) {
	_ = ensureWintunDLL()
	if mtu <= 0 {
		mtu = 1360
	}
	var adapter *wintun.Adapter
	var session wintun.Session
	var err error

	for attempt := 0; attempt < 3; attempt++ {
		adapter, err = wintun.OpenAdapter(name)
		if err == nil {
			session, err = adapter.StartSession(0x800000)
			if err == nil {
				d := &windowsDevice{name: name, mtu: mtu, adapter: adapter, session: session}
				d.sessionOK.Store(true)
				log.Printf("[TUN] Reusing existing Windows adapter: %s (MTU=%d)", name, mtu)
				startCrashGuard()
				return d, nil
			}
			_ = adapter.Close()
			adapter = nil
			time.Sleep(200 * time.Millisecond)
		}
	}

	for attempt := 0; attempt < 5; attempt++ {
		adapter, err = wintun.CreateAdapter(name, "AERO", nil)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
		if a, oerr := wintun.OpenAdapter(name); oerr == nil {
			if s, serr := a.StartSession(0x800000); serr == nil {
				d := &windowsDevice{name: name, mtu: mtu, adapter: a, session: s}
				d.sessionOK.Store(true)
				startCrashGuard()
				return d, nil
			}
			_ = a.Close()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("wintun create adapter: %w", err)
	}

	session, err = adapter.StartSession(0x800000)
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("wintun start session: %w", err)
	}

	d := &windowsDevice{name: name, mtu: mtu, adapter: adapter, session: session}
	d.sessionOK.Store(true)
	log.Printf("[TUN] Windows adapter created: %s (MTU=%d)", name, mtu)
	startCrashGuard()
	return d, nil
}

func (d *windowsDevice) Read(p []byte) (int, error) {
	if d.closed.Load() || !d.sessionOK.Load() {
		return 0, fmt.Errorf("device closed")
	}
	for {
		if d.closed.Load() {
			return 0, fmt.Errorf("device closed")
		}
		packet, err := d.session.ReceivePacket()
		if err != nil {
			if err == errorNoMoreItems || strings.Contains(err.Error(), "No more data") {
				ev := d.session.ReadWaitEvent()
				res, _ := windows.WaitForSingleObject(ev, 1000)
				if res == uint32(windows.WAIT_TIMEOUT) {
					continue
				}
				continue
			}
			if !d.closed.Load() && d.adapter != nil {
				d.session.End()
				time.Sleep(300 * time.Millisecond)
				if newSess, nerr := d.adapter.StartSession(0x800000); nerr == nil {
					d.session = newSess
					continue
				}
			}
			return 0, err
		}
		n := copy(p, packet)
		d.session.ReleaseReceivePacket(packet)
		if n == 0 {
			continue
		}
		return n, nil
	}
}

func (d *windowsDevice) Write(p []byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed.Load() || !d.sessionOK.Load() {
		return 0, fmt.Errorf("device closed")
	}
	if len(p) == 0 {
		return 0, nil
	}
	buf, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		if !d.closed.Load() && d.adapter != nil {
			d.session.End()
			if newSess, nerr := d.adapter.StartSession(0x800000); nerr == nil {
				d.session = newSess
				buf, err = d.session.AllocateSendPacket(len(p))
			}
		}
		if err != nil {
			return 0, err
		}
	}
	copy(buf, p)
	d.session.SendPacket(buf)
	return len(p), nil
}

func (d *windowsDevice) Close() error {
	stopCrashGuard()
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	if d.sessionOK.CompareAndSwap(true, false) {
		d.session.End()
	}
	if d.adapter != nil {
		d.adapter.Close()
		d.adapter = nil
	}
	log.Printf("[TUN] Windows adapter closed: %s", d.name)
	return nil
}

func (d *windowsDevice) Name() string { return d.name }

// SetInterfaceMTU 动态修改虚拟网卡 MTU
func SetInterfaceMTU(devName string, mtu int) error {
	if devName == "" {
		devName = "aero0"
	}
	return runCmd("netsh", "interface", "ipv4", "set", "subinterface", devName, fmt.Sprintf("mtu=%d", mtu), "store=active")
}

// SetupRoutes 配置 Windows 路由与网卡参数
// 规则：初始 MTU 设为 1360；配置 IPv6 黑洞路由（::/1 与 8000::/1 绑定 devName）；配置 NRPT 策略解析至 TUN DNS
func SetupRoutes(devName, ipv4 string) error {
	if devName == "" {
		devName = "aero0"
	}
	tunIP := "10.88.0.2"
	mask := "255.255.255.0"
	if ipv4 != "" {
		parts := strings.Split(ipv4, "/")
		tunIP = parts[0]
		if len(parts) == 2 {
			mask = cidrToMask(parts[1])
		}
	}

	_ = runCmd("netsh", "interface", "ip", "set", "address",
		"name="+devName, "source=static", "addr="+tunIP, "mask="+mask, "gateway=none")
	_ = runCmd("netsh", "interface", "set", "interface", "name="+devName, "admin=ENABLED")
	time.Sleep(300 * time.Millisecond)

	idx := interfaceIndex(devName)

	// 1. 设置初始虚拟网卡 MTU 为 1360
	_ = SetInterfaceMTU(devName, 1360)

	// 注册动态 MTU 回调
	RegisterVirtualNICMTUSetter(func(mtu int) error {
		return SetInterfaceMTU(devName, mtu)
	})

	// 2. 清理旧 split 路由（严格限定仅当前网卡）并添加 0.0.0.0/1 和 128.0.0.0/1
	_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", devName)
	_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", devName)

	addSplitDefault := func(dst, m string) {
		args := []string{"add", dst, "mask", m, tunIP, "metric", "1"}
		if idx != "" {
			args = append(args, "if", idx)
		}
		_ = runCmd("route", args...)
	}
	addSplitDefault("0.0.0.0", "128.0.0.0")
	addSplitDefault("128.0.0.0", "128.0.0.0")

	// 3. IPv6 黑洞路由：在 TUN 网卡上添加 ::/1 和 8000::/1（仅绑定 devName）
	_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "::/1", devName)
	_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "8000::/1", devName)
	_ = runCmd("netsh", "interface", "ipv6", "add", "route", "::/1", devName)
	_ = runCmd("netsh", "interface", "ipv6", "add", "route", "8000::/1", devName)

	// 4. 为虚拟网卡绑定纯净 DNS，使系统将 DNS 流量送入虚拟网卡，被 gVisor 端口 53 拦截处理
	_ = runCmd("netsh", "interface", "ip", "set", "dnsservers", "name="+devName, "source=static", "address=1.1.1.1", "validate=no")
	_ = runCmd("netsh", "interface", "ip", "add", "dnsservers", "name="+devName, "address=8.8.8.8", "index=2", "validate=no")

	// 5. NRPT 策略配置：配置所有域名（Namespace "."）指向 TUN 网卡 DNS（tunIP），标记 Comment 为 "AERO_" + devName。不改动任何物理网卡的 DNS！
	_ = runCmd("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Add-DnsClientNrptRule -Namespace '.' -NameServers '%s' -Comment 'AERO_%s'", tunIP, devName))

	log.Printf("[TUN] Routes and DNS configured on %s via %s if=%s (MTU=1360)", devName, tunIP, idx)
	return nil
}

// TeardownRoutes 清理 Windows 路由与 DNS（严格限定在 aero0 接口上，绝对不误删宿主机或其他 VPN 路由）
func TeardownRoutes(devName string) {
	if devName == "" {
		devName = "aero0"
	}
	_ = runCmd("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'AERO_%s' } | Remove-DnsClientNrptRule -Force", devName))
	_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "::/1", devName)
	_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "8000::/1", devName)
	_ = runCmd("netsh", "interface", "ip", "set", "dnsservers", "name="+devName, "source=dhcp")
	_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", devName)
	_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", devName)
	log.Printf("[TUN] Routes and DNS removed for %s", devName)
}

// CleanAero0StaleRoutes 仅删除归属于 aero0 接口的 0.0.0.0/1 和 128.0.0.0/1 及 DNS，碰不到任何其他网卡
func CleanAero0StaleRoutes() {
	_ = runCmd("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'AERO_aero0' } | Remove-DnsClientNrptRule -Force")
	_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "::/1", "aero0")
	_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "8000::/1", "aero0")
	_ = runCmd("netsh", "interface", "ip", "set", "dnsservers", "name=aero0", "source=dhcp")
	_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", "aero0")
	_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", "aero0")
}

// getWindowsAdaptersSummary 通过原生 IP Helper API 采集完整的网卡描述与 IfType
func getWindowsAdaptersSummary() ([]ifaceSummary, error) {
	var size uint32 = 15000
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		p := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		flags := uint32(windows.GAA_FLAG_INCLUDE_ALL_INTERFACES | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER)
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, p, &size)
		if err == nil {
			var summaries []ifaceSummary
			for curr := p; curr != nil; curr = curr.Next {
				name := windows.UTF16PtrToString(curr.FriendlyName)
				desc := windows.UTF16PtrToString(curr.Description)
				isUp := (curr.OperStatus == windows.IfOperStatusUp)
				isLoopback := (curr.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK)

				var ips []net.IP
				for u := curr.FirstUnicastAddress; u != nil; u = u.Next {
					if ip := u.Address.IP(); ip != nil {
						ips = append(ips, ip)
					}
				}
				summaries = append(summaries, ifaceSummary{
					Name:        name,
					Description: desc,
					IfType:      curr.IfType,
					IsUp:        isUp,
					IsLoopback:  isLoopback,
					IPs:         ips,
				})
			}
			return summaries, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}
	return nil, fmt.Errorf("GetAdaptersAddresses buffer overflow")
}

// DetectThirdPartyTUN 检测宿主机是否存在其他正在运行 TUN 模式的 VPN
func DetectThirdPartyTUN() (bool, string, error) {
	summaries, err := getWindowsAdaptersSummary()
	if err != nil {
		return false, "", fmt.Errorf("query adapters: %w", err)
	}

	prt := exec.Command("route", "print", "-4")
	prt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := prt.CombinedOutput()
	if err != nil {
		return false, "", fmt.Errorf("route print failed: %w", err)
	}

	conflict, name := evaluateThirdPartyTUN(summaries, string(out))
	return conflict, name, nil
}

func liveIfIndexByName(name string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	target := strings.ToLower(name)
	for _, ifi := range ifaces {
		if strings.ToLower(ifi.Name) == target {
			return strconv.Itoa(ifi.Index)
		}
	}
	return ""
}

var routeCmd = runCmd

func deleteHostRoutes(host string) (residue bool) {
	for i := 0; i < 5; i++ {
		if err := routeCmd("route", "delete", host, "mask", "255.255.255.255"); err != nil {
			return false
		}
	}
	return true
}

func isRouteParameterError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "access is denied") || strings.Contains(s, "拒绝访问") {
		return false
	}
	return strings.Contains(s, "parameter is incorrect") ||
		strings.Contains(s, "参数不正确") ||
		strings.Contains(s, "参数错误")
}

func addHostRoute(host, gw, ifIndex string) error {
	args := []string{"add", host, "mask", "255.255.255.255", gw, "metric", "1"}
	if ifIndex != "" {
		args = append(args, "if", ifIndex)
	}
	err := routeCmd("route", args...)
	if err == nil {
		return nil
	}

	if isRouteParameterError(err) {
		if ifIndex == "" {
			return err
		}
		fallbackArgs := []string{"add", host, "mask", "255.255.255.255", "0.0.0.0", "metric", "1", "if", ifIndex}
		return routeCmd("route", fallbackArgs...)
	}

	if ifIndex != "" {
		retryArgs := []string{"add", host, "mask", "255.255.255.255", gw, "metric", "1"}
		return routeCmd("route", retryArgs...)
	}

	return err
}

// ProtectHostRoute 保护海外 VPS 节点直连路由
// 注意：addHostRoute 中的第二段回退命令 (0.0.0.0 if <ifIndex>) 尚未在真实 PPPoE 拨号上验证
func ProtectHostRoute(hostIP string) error {
	ip := net.ParseIP(hostIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	if deleteHostRoutes(hostIP) {
		log.Printf("[TUN] host route %s still has residue after 5 delete attempts", hostIP)
	}

	gw, ifIndex, err := PhysicalDefaultGateway()
	if err != nil || gw == "" {
		return err
	}

	return addHostRoute(hostIP, gw, ifIndex)
}

// UnprotectHostRoute 移除海外节点保护路由
func UnprotectHostRoute(hostIP string) {
	if hostIP == "" {
		return
	}
	ip := net.ParseIP(hostIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return
	}
	if deleteHostRoutes(hostIP) {
		log.Printf("[TUN] host route %s still has residue after 5 delete attempts", hostIP)
	}
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

type cachedGateway struct {
	gw      string
	ifIndex string
	updated time.Time
}

var (
	gwCacheMu sync.RWMutex
	lastGW    cachedGateway
)

func invalidateGatewayCache() {
	gwCacheMu.Lock()
	lastGW = cachedGateway{}
	gwCacheMu.Unlock()
}

// PhysicalDefaultGateway 获取物理默认网关与网卡索引（彻底排除一切虚拟/VPN网卡，严防流量被引向他人隧道）
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	gwCacheMu.RLock()
	if lastGW.gw != "" && time.Since(lastGW.updated) < 15*time.Second {
		cachedGW, cachedIdx := lastGW.gw, lastGW.ifIndex
		gwCacheMu.RUnlock()
		return cachedGW, cachedIdx, nil
	}
	gwCacheMu.RUnlock()

	summaries, _ := getWindowsAdaptersSummary()
	prt := exec.Command("route", "print", "-4")
	prt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, e := prt.CombinedOutput()
	if e != nil {
		return "", "", e
	}
	bestGW, bestIdx, err := physicalDefaultGatewayWithInput(summaries, string(out), liveIfIndexForIPv4)
	if err != nil {
		return "", "", err
	}

	gwCacheMu.Lock()
	lastGW = cachedGateway{
		gw:      bestGW,
		ifIndex: bestIdx,
		updated: time.Now(),
	}
	gwCacheMu.Unlock()

	return bestGW, bestIdx, nil
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
		if strings.Contains(strings.ToLower(ifi.Name), "aero") {
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

// DialPhysicalDirect 绑定物理网卡发包
func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	if hook := getPhysicalDialerHook(); hook != nil {
		return hook(ctx, network, addr)
	}
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	if !isLoopbackHost(addr) {
		_, idxStr, err := PhysicalDefaultGateway()
		if err == nil && idxStr != "" {
			if idx, err := strconv.Atoi(idxStr); err == nil && idx > 0 {
				dialer.Control = func(netw, address string, c syscall.RawConn) error {
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
	}
	return dialer.DialContext(ctx, network, addr)
}

// ListenPhysicalPacket 绑定物理网卡监听
func ListenPhysicalPacket(ctx context.Context, network string) (net.PacketConn, error) {
	_, idxStr, err := PhysicalDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("physical default gateway: %w", err)
	}
	if idxStr == "" {
		return nil, fmt.Errorf("physical interface index not found")
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx <= 0 {
		return nil, fmt.Errorf("invalid physical interface index %q", idxStr)
	}
	var lc net.ListenConfig
	lc.Control = func(netw, address string, c syscall.RawConn) error {
		var opErr error
		_ = c.Control(func(fd uintptr) {
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], uint32(idx))
			opErr = syscall.Setsockopt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, (*byte)(unsafe.Pointer(&buf[0])), 4)
		})
		return opErr
	}
	return lc.ListenPacket(ctx, network, ":0")
}

var (
	cmdExecutorMu sync.RWMutex
	cmdExecutor   func(name string, args ...string) error
)

// SetCmdExecutorForTest sets the command execution hook for unit testing and returns a restore function.
func SetCmdExecutorForTest(f func(name string, args ...string) error) func() {
	cmdExecutorMu.Lock()
	orig := cmdExecutor
	cmdExecutor = f
	cmdExecutorMu.Unlock()
	return func() {
		cmdExecutorMu.Lock()
		cmdExecutor = orig
		cmdExecutorMu.Unlock()
	}
}

func runCmd(name string, args ...string) error {
	clean := make([]string, 0, len(args))
	for _, a := range args {
		if a != "" {
			clean = append(clean, a)
		}
	}

	cmdExecutorMu.RLock()
	execFn := cmdExecutor
	cmdExecutorMu.RUnlock()
	if execFn != nil {
		return execFn(name, clean...)
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
