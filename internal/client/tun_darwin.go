//go:build darwin && !ios

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
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

type darwinDevice struct {
	name string
	file *os.File
	mtu  int
}

type darwinDNSBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
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
