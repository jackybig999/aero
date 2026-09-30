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
	"strings"
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
		devName = "utun0"
	}
	return runMac("ifconfig", devName, "mtu", fmt.Sprintf("%d", mtu))
}

// SetupRoutes 配置 macOS 路由
func SetupRoutes(devName, ipv4 string) error {
	if devName == "" {
		devName = "utun0"
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
		devName = "utun0"
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

// PhysicalDefaultGateway 获取物理网关与网卡
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	out, e := exec.Command("route", "-n", "get", "default").CombinedOutput()
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
	if gw == "" {
		return "", "", fmt.Errorf("no physical default gateway")
	}
	return gw, ifIndex, nil
}

const ipBoundIF = 25

// DialPhysicalDirect 绑定 macOS 物理网卡直连 (IP_BOUND_IF)
func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
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
