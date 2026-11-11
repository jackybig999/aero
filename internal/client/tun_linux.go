//go:build linux && !android

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const tunDevice = "/dev/net/tun"

// newClientTunIfreq 构造 TUNSETIFF 请求。必须使用 unix.Ifreq：其大小与内核
// struct ifreq（40 字节）一致；内核会按该大小回写，自定义的短结构体会被越界写。
func newClientTunIfreq(name string) (*unix.Ifreq, error) {
	if name == "" {
		return nil, errors.New("TUN device name is empty")
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, fmt.Errorf("TUN device name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	return ifr, nil
}

type linuxDevice struct {
	name string
	file *os.File
	mtu  int
}

// OpenTunDevice 创建 Linux TUN 设备
func OpenTunDevice(name string, mtu int) (TunDevice, error) {
	if mtu <= 0 {
		mtu = 1360
	}
	file, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}

	ifr, err := newClientTunIfreq(name)
	if err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("%v; close %s: %w", err, tunDevice, closeErr)
		}
		return nil, err
	}
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifr); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("TUNSETIFF: %v; close %s: %w", err, tunDevice, closeErr)
		}
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}
	devName := ifr.Name()

	return &linuxDevice{name: devName, file: file, mtu: mtu}, nil
}

func (d *linuxDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *linuxDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *linuxDevice) Close() error                { return d.file.Close() }
func (d *linuxDevice) Name() string                { return d.name }

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

var (
	linuxCmdExecutorMu sync.RWMutex
	linuxCmdExecutor   func(name string, args ...string) error
)

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
