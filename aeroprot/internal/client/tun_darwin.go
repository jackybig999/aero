//go:build darwin && !ios

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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type darwinDevice struct {
	name string
	file *os.File
	mtu  int
}

// OpenTunDevice 创建 macOS utun 设备
func OpenTunDevice(name string, mtu int) (TunDevice, error) {
	if mtu <= 0 {
		mtu = 1224
	}
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	var devName string
	for id := 0; id < 32; id++ {
		err = unix.Connect(fd, &unix.SockaddrCtl{
			ID:   2,
			Unit: uint32(id + 1),
		})
		if err == nil {
			devName = fmt.Sprintf("utun%d", id)
			break
		}
	}
	if devName == "" {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("no free utun device")
	}

	if err := writeUtunRecord(devName); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("write utun record: %w", err)
	}

	file := os.NewFile(uintptr(fd), devName)
	return &darwinDevice{name: devName, file: file, mtu: mtu}, nil
}

func (d *darwinDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *darwinDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *darwinDevice) Close() error                { return d.file.Close() }
func (d *darwinDevice) Name() string                { return d.name }

// SetInterfaceMTU 暴露 macOS 动态修改网卡 MTU 接口
func SetInterfaceMTU(devName string, mtu int) error {
	if devName == "" {
		return fmt.Errorf("empty devName")
	}
	return runMac("ifconfig", devName, "mtu", fmt.Sprintf("%d", mtu))
}

// SetupRoutes 配置 macOS 路由
func SetupRoutes(devName, ipv4 string) error {
	if devName == "" {
		return fmt.Errorf("empty devName")
	}
	tunIP := "10.88.0.2"
	if ipv4 != "" {
		tunIP = strings.Split(ipv4, "/")[0]
	}
	_ = runMac("ifconfig", devName, "inet", tunIP, tunIP)
	_ = runMac("ifconfig", devName, "up")

	_ = SetInterfaceMTU(devName, 1224)
	RegisterVirtualNICMTUSetter(func(mtu int) error {
		return SetInterfaceMTU(devName, mtu)
	})

	_ = runMac("route", "add", "-net", "0.0.0.0/1", "-interface", devName)
	_ = runMac("route", "add", "-net", "128.0.0.0/1", "-interface", devName)

	log.Printf("[TUN] Routes configured on %s (MTU=1224)", devName)
	return nil
}

// TeardownRoutes 清理 macOS 路由
func TeardownRoutes(devName string) {
	if devName == "" {
		return
	}
	_ = runMac("route", "delete", "-net", "0.0.0.0/1", "-interface", devName)
	_ = runMac("route", "delete", "-net", "128.0.0.0/1", "-interface", devName)
	log.Printf("[TUN] Routes removed for %s", devName)
}

// ProtectHostRoute 保护海外节点路由
func ProtectHostRoute(hostIP string) error {
	ip := net.ParseIP(hostIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	gw, _, err := PhysicalDefaultGateway()
	if err != nil || gw == "" {
		return err
	}
	_ = runMac("route", "-n", "delete", "-host", hostIP)
	return runMac("route", "-n", "add", "-host", hostIP, gw)
}

// UnprotectHostRoute 移除保护路由
func UnprotectHostRoute(hostIP string) {
	if hostIP == "" {
		return
	}
	_ = runMac("route", "-n", "delete", "-host", hostIP)
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

// isDarwinVirtualDev 判定 macOS 接口是否为虚拟/TUN/VPN接口
func isDarwinVirtualDev(dev string) bool {
	devLower := strings.ToLower(dev)
	if devLower == "aero0" || devLower == "lo0" {
		return false
	}
	prefixes := []string{"utun", "ipsec", "tap", "tun"}
	for _, p := range prefixes {
		if strings.HasPrefix(devLower, p) {
			return true
		}
	}
	return false
}

// PhysicalDefaultGateway 获取物理网关与网卡（严格跳过 utun 虚拟网卡）
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	gwCacheMu.RLock()
	if lastGW.gw != "" && time.Since(lastGW.updated) < 15*time.Second {
		cachedGW, cachedIdx := lastGW.gw, lastGW.ifIndex
		gwCacheMu.RUnlock()
		return cachedGW, cachedIdx, nil
	}
	gwCacheMu.RUnlock()

	// 先尝试从 netstat -rn -f inet 寻找实体物理接口 (en0, en1...) 上的 default 路由
	out, e := exec.Command("netstat", "-rn", "-f", "inet").CombinedOutput()
	if e == nil {
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			fields := strings.Fields(l)
			if len(fields) >= 4 && fields[0] == "default" {
				candidateGW := fields[1]
				candidateDev := fields[len(fields)-1]
				if !isDarwinVirtualDev(candidateDev) && net.ParseIP(candidateGW) != nil {
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
		}
	}

	// 降级使用 route -n get default
	out, e = exec.Command("route", "-n", "get", "default").CombinedOutput()
	if e != nil {
		return "", "", e
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) >= 2 {
			if fields[0] == "gateway:" {
				gw = fields[1]
			}
			if fields[0] == "interface:" {
				ifIndex = fields[1]
			}
		}
	}
	if gw == "" || isDarwinVirtualDev(ifIndex) {
		return "", "", fmt.Errorf("no physical default gateway")
	}

	gwCacheMu.Lock()
	lastGW = cachedGateway{
		gw:      gw,
		ifIndex: ifIndex,
		updated: time.Now(),
	}
	gwCacheMu.Unlock()

	return gw, ifIndex, nil
}

const ipBoundIF = 25

// DialPhysicalDirect 绑定 macOS 物理网卡直连 (IP_BOUND_IF)
func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	if hook := getPhysicalDialerHook(); hook != nil {
		return hook(ctx, network, addr)
	}
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	if !isLoopbackHost(addr) {
		_, ifName, err := PhysicalDefaultGateway()
		if err == nil && ifName != "" && !strings.Contains(strings.ToLower(ifName), "aero") {
			if ifi, ierr := net.InterfaceByName(ifName); ierr == nil && ifi.Index > 0 {
				dialer.Control = func(netw, address string, c syscall.RawConn) error {
					var opErr error
					_ = c.Control(func(fd uintptr) {
						opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipBoundIF, ifi.Index)
					})
					return opErr
				}
			}
		}
	}
	return dialer.DialContext(ctx, network, addr)
}

// ListenPhysicalPacket 监听物理网络包 (IP_BOUND_IF)
func ListenPhysicalPacket(ctx context.Context, network string) (net.PacketConn, error) {
	_, ifName, err := PhysicalDefaultGateway()
	var lc net.ListenConfig
	if err == nil && ifName != "" && !strings.Contains(strings.ToLower(ifName), "aero") {
		if ifi, ierr := net.InterfaceByName(ifName); ierr == nil && ifi.Index > 0 {
			lc.Control = func(netw, address string, c syscall.RawConn) error {
				var opErr error
				_ = c.Control(func(fd uintptr) {
					opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipBoundIF, ifi.Index)
				})
				return opErr
			}
		}
	}
	return lc.ListenPacket(ctx, network, ":0")
}

func runMac(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func validUtunName(name string) bool {
	if !strings.HasPrefix(name, "utun") {
		return false
	}
	numStr := strings.TrimPrefix(name, "utun")
	if numStr == "" {
		return false
	}
	for i := 0; i < len(numStr); i++ {
		if numStr[i] < '0' || numStr[i] > '9' {
			return false
		}
	}
	if len(numStr) > 1 && numStr[0] == '0' {
		return false
	}
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return false
	}
	return n >= 0 && n <= 31
}

func shouldCleanUtun(name, ifconfigText string, ifaceExists bool) bool {
	if !validUtunName(name) {
		return false
	}
	if !ifaceExists {
		return true
	}
	return strings.Contains(ifconfigText, "inet 10.88.0.2")
}

func writeUtunRecord(name string) error {
	p := utunRecordPath()
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "utun.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.WriteString(name + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

func readUtunRecord() (string, error) {
	p := utunRecordPath()
	data, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func removeUtunRecord() {
	p := utunRecordPath()
	_ = os.Remove(p)
}

// CleanAero0StaleRoutes 清理 macOS 残留路由（仅针对 AERO 打开且仍持有 10.88.0.2 的 utun 网卡）
func CleanAero0StaleRoutes() {
	name, err := readUtunRecord()
	if err != nil || name == "" {
		return
	}

	if !validUtunName(name) {
		removeUtunRecord()
		return
	}

	out, err := exec.Command("ifconfig", name).CombinedOutput()
	ifaceExists := (err == nil)
	ifconfigText := string(out)

	if shouldCleanUtun(name, ifconfigText, ifaceExists) {
		if ifaceExists {
			_ = runMac("route", "delete", "-net", "0.0.0.0/1", "-interface", name)
			_ = runMac("route", "delete", "-net", "128.0.0.0/1", "-interface", name)
		}
		removeUtunRecord()
	} else {
		log.Printf("[TUN] utun %s address mismatch, removing record without modifying routes", name)
		removeUtunRecord()
	}
}

// DetectThirdPartyTUN 检测 macOS 第三方 TUN
func DetectThirdPartyTUN() (bool, string, error) {
	// 条件 1: 扫描所有 UP 网卡是否分配了 198.18.0.0/15 地址 (Clash / Surge / Loon Fake-IP)
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

	// 条件 2: 检查 macOS 路由表 netstat -rn -f inet
	out, err := exec.Command("netstat", "-rn", "-f", "inet").CombinedOutput()
	if err != nil {
		return false, "", nil
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 4 {
			continue
		}
		dest := fields[0]
		dev := fields[len(fields)-1]

		// 条件 2a: 检查 0/1 或 128/1 或 0.0.0.0/1 或 128.0.0.0/1
		if dest == "0/1" || dest == "128/1" || dest == "0.0.0.0/1" || dest == "128.0.0.0/1" {
			if !strings.EqualFold(dev, "aero0") {
				return true, dev, nil
			}
		}
		// 条件 2b: 默认路由指向虚拟网卡 (utun*, ppp*)
		if dest == "default" && isDarwinVirtualDev(dev) {
			return true, dev, nil
		}
	}

	return false, "", nil
}
