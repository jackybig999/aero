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
	"syscall"
	"time"
	"unsafe"
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

	log.Printf("[TUN] Routes configured on %s (MTU=1224)", devName)
	return nil
}

// TeardownRoutes 清理 Linux 路由
func TeardownRoutes(devName string) {
	if devName == "" {
		devName = "aero0"
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

// PhysicalDefaultGateway 获取物理默认网关与网卡名
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	out, e := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if e != nil {
		return "", "", e
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		for i := 0; i+2 < len(fields); i++ {
			if fields[i] == "via" {
				gw = fields[i+1]
			}
			if fields[i] == "dev" {
				ifIndex = fields[i+1]
			}
		}
		if gw != "" {
			return gw, ifIndex, nil
		}
	}
	return "", "", fmt.Errorf("no physical default gateway")
}

// DialPhysicalDirect 绑定 Linux 物理网卡直连
func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	dialer.Timeout = 8 * time.Second
	return dialer.DialContext(ctx, network, addr)
}

// ListenPhysicalPacket 监听物理网络包
func ListenPhysicalPacket(ctx context.Context, network string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, ":0")
}

func runLinux(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
