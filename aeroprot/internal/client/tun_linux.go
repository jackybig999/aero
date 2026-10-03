//go:build linux && !android

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunDevice = "/dev/net/tun"
	iffTun    = 0x0001
	iffNoPi   = 0x1000
	tunSetIff = 0x400454ca
)

type linuxDevice struct {
	name string
	file *os.File
	mtu  int
}

// OpenTunDevice 创建 Linux TUN 设备
func OpenTunDevice(name string, mtu int) (TunDevice, error) {
	if mtu <= 0 {
		mtu = 1224
	}
	file, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}

	ifr := struct {
		name  [16]byte
		flags uint16
	}{flags: iffTun | iffNoPi}
	copy(ifr.name[:], name)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(tunSetIff),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("TUNSETIFF: %v", errno)
	}

	devName := string(ifr.name[:])
	for i, b := range ifr.name {
		if b == 0 {
			devName = string(ifr.name[:i])
			break
		}
	}

	return &linuxDevice{name: devName, file: file, mtu: mtu}, nil
}

func (d *linuxDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *linuxDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *linuxDevice) Close() error                { return d.file.Close() }
func (d *linuxDevice) Name() string                { return d.name }

// SetInterfaceMTU 暴露 Linux 动态修改网卡 MTU 接口
func SetInterfaceMTU(devName string, mtu int) error {
	if devName == "" {
		devName = "aero0"
	}
	return runLinux("ip", "link", "set", "dev", devName, "mtu", fmt.Sprintf("%d", mtu))
}

// SetupLinuxDNS 配置 Linux DNS 零泄露保护：优先使用 systemd-resolved，降级原子备份 /etc/resolv.conf
func SetupLinuxDNS(dev ...string) error {
	devName := "aero0"
	if len(dev) > 0 && dev[0] != "" {
		devName = dev[0]
	}

	// a) 优先检测 systemd-resolved (resolvectl 或 systemd-resolve)
	if _, err := exec.LookPath("resolvectl"); err == nil {
		if err := runLinux("resolvectl", "dns", devName, "1.1.1.1", "8.8.8.8"); err == nil {
			_ = runLinux("resolvectl", "domain", devName, "~.")
			log.Printf("[TUN] Linux DNS configured via resolvectl on %s (1.1.1.1 8.8.8.8, domain ~.)", devName)
			return nil
		}
	}
	if _, err := exec.LookPath("systemd-resolve"); err == nil {
		if err := runLinux("systemd-resolve", "-i", devName, "--set-dns=1.1.1.1", "--set-dns=8.8.8.8", "--set-domain=~."); err == nil {
			log.Printf("[TUN] Linux DNS configured via systemd-resolve on %s", devName)
			return nil
		}
	}

	// b) 若不可用，将 /etc/resolv.conf 原子备份到 /etc/resolv.conf.aero.bak，写入 1.1.1.1
	const (
		resolvConf    = "/etc/resolv.conf"
		resolvConfBak = "/etc/resolv.conf.aero.bak"
		resolvConfTmp = "/etc/resolv.conf.aero.tmp"
	)

	if _, err := os.Stat(resolvConfBak); os.IsNotExist(err) {
		orig, rerr := os.ReadFile(resolvConf)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", resolvConf, rerr)
		}
		bakTmp := resolvConfBak + ".tmp"
		if werr := os.WriteFile(bakTmp, orig, 0644); werr != nil {
			return fmt.Errorf("write %s: %w", bakTmp, werr)
		}
		if renErr := os.Rename(bakTmp, resolvConfBak); renErr != nil {
			_ = os.Remove(bakTmp)
			return fmt.Errorf("rename to %s: %w", resolvConfBak, renErr)
		}
	}

	newContent := []byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
	if err := os.WriteFile(resolvConfTmp, newContent, 0644); err != nil {
		return fmt.Errorf("write %s: %w", resolvConfTmp, err)
	}
	if err := os.Rename(resolvConfTmp, resolvConf); err != nil {
		_ = os.Remove(resolvConfTmp)
		return fmt.Errorf("replace %s: %w", resolvConf, err)
	}

	log.Printf("[TUN] Linux DNS configured via %s (backup at %s)", resolvConf, resolvConfBak)
	return nil
}

// RestoreLinuxDNS 还原 Linux DNS 配置
func RestoreLinuxDNS(dev ...string) error {
	devName := "aero0"
	if len(dev) > 0 && dev[0] != "" {
		devName = dev[0]
	}

	var firstErr error

	// 1. 若存在 /etc/resolv.conf.aero.bak，使用 os.Rename 还原
	const (
		resolvConf    = "/etc/resolv.conf"
		resolvConfBak = "/etc/resolv.conf.aero.bak"
	)
	if _, err := os.Stat(resolvConfBak); err == nil {
		if err := os.Rename(resolvConfBak, resolvConf); err != nil {
			firstErr = fmt.Errorf("restore %s from %s: %w", resolvConf, resolvConfBak, err)
		} else {
			log.Printf("[TUN] Restored %s from %s", resolvConf, resolvConfBak)
		}
	}

	// 2. 若使用 systemd-resolved，执行 revert
	if _, err := exec.LookPath("resolvectl"); err == nil {
		_ = runLinux("resolvectl", "revert", devName)
	} else if _, err := exec.LookPath("systemd-resolve"); err == nil {
		_ = runLinux("systemd-resolve", "--revert", "-i", devName)
	}

	return firstErr
}

// SetupRoutes 配置 Linux 路由
func SetupRoutes(devName, ipv4 string) error {
	if devName == "" {
		devName = "aero0"
	}
	if err := runLinux("ip", "link", "set", devName, "up"); err != nil {
		return err
	}
	if ipv4 == "" {
		ipv4 = "10.88.0.2/24"
	}
	_ = runLinux("ip", "addr", "add", ipv4, "dev", devName)

	_ = SetInterfaceMTU(devName, 1224)
	RegisterVirtualNICMTUSetter(func(mtu int) error {
		return SetInterfaceMTU(devName, mtu)
	})

	_ = runLinux("ip", "route", "replace", "0.0.0.0/1", "dev", devName)
	_ = runLinux("ip", "route", "replace", "128.0.0.0/1", "dev", devName)

	if err := SetupLinuxDNS(devName); err != nil {
		log.Printf("[TUN] Linux DNS configuration warning: %v", err)
	}

	log.Printf("[TUN] Routes configured on %s (MTU=1224)", devName)
	return nil
}

// TeardownRoutes 清理 Linux 路由
func TeardownRoutes(devName string) {
	if devName == "" {
		devName = "aero0"
	}
	if err := RestoreLinuxDNS(devName); err != nil {
		log.Printf("[TUN] Linux DNS restore warning: %v", err)
	}
	_ = runLinux("ip", "route", "del", "0.0.0.0/1", "dev", devName)
	_ = runLinux("ip", "route", "del", "128.0.0.0/1", "dev", devName)
	log.Printf("[TUN] Routes removed for %s", devName)
}

// ProtectHostRoute 保护海外节点路由
func ProtectHostRoute(hostIP string) error {
	ip := net.ParseIP(hostIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	gw, iface, err := PhysicalDefaultGateway()
	if err != nil || gw == "" {
		return err
	}
	args := []string{"route", "replace", hostIP + "/32", "via", gw}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	return runLinux("ip", args...)
}

// UnprotectHostRoute 移除保护路由
func UnprotectHostRoute(hostIP string) {
	if hostIP == "" {
		return
	}
	_ = runLinux("ip", "route", "del", hostIP+"/32")
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

// isLinuxVirtualDev 判定 Linux 接口是否为虚拟/TUN/VPN接口
func isLinuxVirtualDev(dev string) bool {
	devLower := strings.ToLower(dev)
	if devLower == "aero0" || devLower == "lo" {
		return false
	}
	// 1. Linux 内核驱动 drivers/net/tun.c: 检查 /sys/class/net/<dev>/tun_flags
	if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/tun_flags", dev)); err == nil {
		return true
	}
	// 2. WireGuard / 其他虚拟 VPN 网卡特征
	prefixes := []string{"tun", "tap", "wg", "tailscale", "meta", "clash", "sing-box", "singbox"}
	for _, p := range prefixes {
		if strings.HasPrefix(devLower, p) {
			return true
		}
	}
	return false
}

// PhysicalDefaultGateway 获取物理默认网关与网卡名（严格跳过虚拟/TUN网卡）
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	gwCacheMu.RLock()
	if lastGW.gw != "" && time.Since(lastGW.updated) < 15*time.Second {
		cachedGW, cachedIdx := lastGW.gw, lastGW.ifIndex
		gwCacheMu.RUnlock()
		return cachedGW, cachedIdx, nil
	}
	gwCacheMu.RUnlock()

	out, e := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if e != nil {
		return "", "", e
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		candidateGW := ""
		candidateDev := ""
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "via" {
				candidateGW = fields[i+1]
			}
			if fields[i] == "dev" {
				candidateDev = fields[i+1]
			}
		}
		// 跳过虚拟设备以防将 SO_BINDTODEVICE 绑定至第三方 VPN 隧道
		if candidateDev != "" && isLinuxVirtualDev(candidateDev) {
			continue
		}
		if candidateGW != "" && candidateDev != "" {
			gwCacheMu.Lock()
			lastGW = cachedGateway{
				gw:      candidateGW,
				ifIndex: candidateDev,
				updated: time.Now(),
			}
			gwCacheMu.Unlock()
			return candidateGW, candidateDev, nil
		}
	}
	return "", "", fmt.Errorf("no physical default gateway")
}

// DialPhysicalDirect 绑定 Linux 物理网卡直连 (SO_BINDTODEVICE)
func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	if hook := getPhysicalDialerHook(); hook != nil {
		return hook(ctx, network, addr)
	}
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	if !isLoopbackHost(addr) {
		_, ifName, err := PhysicalDefaultGateway()
		if err == nil && ifName != "" && !strings.Contains(strings.ToLower(ifName), "aero") {
			dialer.Control = func(netw, address string, c syscall.RawConn) error {
				var opErr error
				_ = c.Control(func(fd uintptr) {
					opErr = unix.BindToDevice(int(fd), ifName)
				})
				return opErr
			}
		}
	}
	return dialer.DialContext(ctx, network, addr)
}

// ListenPhysicalPacket 监听物理网络包 (SO_BINDTODEVICE)
func ListenPhysicalPacket(ctx context.Context, network string) (net.PacketConn, error) {
	_, ifName, err := PhysicalDefaultGateway()
	var lc net.ListenConfig
	if err == nil && ifName != "" && !strings.Contains(strings.ToLower(ifName), "aero") {
		lc.Control = func(netw, address string, c syscall.RawConn) error {
			var opErr error
			_ = c.Control(func(fd uintptr) {
				opErr = unix.BindToDevice(int(fd), ifName)
			})
			return opErr
		}
	}
	return lc.ListenPacket(ctx, network, ":0")
}

func runLinux(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CleanAero0StaleRoutes 清理残留路由（仅指定 dev aero0 删除，绝不误伤其他网络）
func CleanAero0StaleRoutes() {
	_ = runLinux("ip", "route", "del", "0.0.0.0/1", "dev", "aero0")
	_ = runLinux("ip", "route", "del", "128.0.0.0/1", "dev", "aero0")
}

// DetectThirdPartyTUN 检测 Linux 第三方 TUN
func DetectThirdPartyTUN() (bool, string, error) {
	// 条件 1: 扫描所有 UP 网卡是否分配了 198.18.0.0/15 地址 (Clash / 透明代理 Fake-IP)
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifi := range ifaces {
			if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 || strings.EqualFold(ifi.Name, "aero0") {
				continue
			}
			addrs, aerr := ifi.Addrs()
			if aerr != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip4 := ip.To4(); ip4 != nil {
					if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
						return true, ifi.Name, nil
					}
				}
			}
		}
	}

	// 条件 2: 检查 Linux 路由表 ip -4 route show
	out, err := exec.Command("ip", "-4", "route", "show").CombinedOutput()
	if err != nil {
		return false, "", nil
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		// 条件 2a: 检查 0.0.0.0/1 或 128.0.0.0/1
		if fields[0] == "0.0.0.0/1" || fields[0] == "128.0.0.0/1" {
			dev := ""
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "dev" {
					dev = fields[i+1]
					break
				}
			}
			if dev != "" && !strings.EqualFold(dev, "aero0") {
				return true, dev, nil
			}
		}
		// 条件 2b: 默认路由指向虚拟网卡 (tun_flags 存在或前缀命中虚拟设备)
		if fields[0] == "default" {
			dev := ""
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "dev" {
					dev = fields[i+1]
					break
				}
			}
			if dev != "" && isLinuxVirtualDev(dev) {
				return true, dev, nil
			}
		}
	}

	return false, "", nil
}
