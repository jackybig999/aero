//go:build windows

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

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
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

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

// OpenTunDevice 打开或创建 Windows Wintun 虚拟网卡（初始 MTU 1224）
func OpenTunDevice(name string, mtu int) (TunDevice, error) {
	if mtu <= 0 {
		mtu = 1224
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
// 规则：初始 MTU 设为 1224；物理删除 fd88::2、IPv6 mtu=1380、::/1、8000::/1；物理删除 netsh advfirewall
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

	// 1. 设置初始虚拟网卡 MTU 为 1224 (1200 + 24)
	_ = SetInterfaceMTU(devName, 1224)

	// 注册动态 MTU 回调
	RegisterVirtualNICMTUSetter(func(mtu int) error {
		return SetInterfaceMTU(devName, mtu)
	})

	// 2. 清理旧 split 路由并添加 0.0.0.0/1 和 128.0.0.0/1
	_ = runCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_ = runCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")

	addSplitDefault := func(dst, m string) {
		args := []string{"add", dst, "mask", m, tunIP, "metric", "1"}
		if idx != "" {
			args = append(args, "if", idx)
		}
		_ = runCmd("route", args...)
	}
	addSplitDefault("0.0.0.0", "128.0.0.0")
	addSplitDefault("128.0.0.0", "128.0.0.0")

	log.Printf("[TUN] Routes configured on %s via %s if=%s (MTU=1224)", devName, tunIP, idx)
	return nil
}

// TeardownRoutes 清理 Windows 路由
func TeardownRoutes(devName string) {
	if devName == "" {
		devName = "aero0"
	}
	_ = runCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_ = runCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", devName)
	_ = runCmd("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", devName)
	log.Printf("[TUN] Routes removed for %s", devName)
}

// ProtectHostRoute 保护海外 VPS 节点直连路由
func ProtectHostRoute(hostIP string) error {
	ip := net.ParseIP(hostIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	gw, ifIndex, err := PhysicalDefaultGateway()
	if err != nil || gw == "" {
		return err
	}
	_ = runCmd("route", "delete", hostIP)
	args := []string{"add", hostIP, "mask", "255.255.255.255", gw, "metric", "1"}
	if ifIndex != "" {
		args = append(args, "if", ifIndex)
	}
	if err := runCmd("route", args...); err != nil {
		args = []string{"add", hostIP, "mask", "255.255.255.255", gw, "metric", "1"}
		return runCmd("route", args...)
	}
	return nil
}

// UnprotectHostRoute 移除海外节点保护路由
func UnprotectHostRoute(hostIP string) {
	if hostIP == "" {
		return
	}
	_ = runCmd("route", "delete", hostIP)
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

type ipv4Default struct {
	gw      string
	ifaceIP net.IP
	metric  int
}

// PhysicalDefaultGateway 获取物理默认网关与网卡索引
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	gwCacheMu.RLock()
	if lastGW.gw != "" && time.Since(lastGW.updated) < 15*time.Second {
		cachedGW, cachedIdx := lastGW.gw, lastGW.ifIndex
		gwCacheMu.RUnlock()
		return cachedGW, cachedIdx, nil
	}
	gwCacheMu.RUnlock()

	prt := exec.Command("route", "print", "-4")
	prt.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, e := prt.CombinedOutput()
	if e != nil {
		return "", "", e
	}
	var best ipv4Default
	bestIdx := ""
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		cand := fields[2]
		if net.ParseIP(cand) == nil || strings.HasPrefix(cand, "10.88.") {
			continue
		}
		ip := net.ParseIP(fields[3])
		if ip == nil || ip.To4() == nil || strings.HasPrefix(ip.String(), "10.88.") {
			continue
		}
		metric := 9999
		if len(fields) >= 5 {
			if n, err := strconv.Atoi(fields[4]); err == nil {
				metric = n
			}
		}
		idx := liveIfIndexForIPv4(ip.To4())
		if idx == "" {
			continue
		}
		if !found || metric < best.metric {
			best = ipv4Default{gw: cand, ifaceIP: ip.To4(), metric: metric}
			bestIdx = idx
			found = true
		}
	}
	if !found {
		return "", "", fmt.Errorf("no physical default gateway")
	}

	gwCacheMu.Lock()
	lastGW = cachedGateway{
		gw:      best.gw,
		ifIndex: bestIdx,
		updated: time.Now(),
	}
	gwCacheMu.Unlock()

	return best.gw, bestIdx, nil
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
