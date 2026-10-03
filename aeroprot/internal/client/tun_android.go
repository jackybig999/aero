//go:build android

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// 契约注释：
// 1. fd 必须由 Android 系统层 VpnService (如 VpnService.Builder.establish()) 创建并传递；
// 2. 排除路由只放节点地址，由系统底层网络栈维护，避免隧道死循环；
// 3. 严禁调用桌面端 route.exe 与 netsh 等宿主机特权指令。

package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// StartTunnel 启动 Android 移动端 TUN 转发隧道。
// 当 fd <= 0 时，返回错误 fmt.Errorf("TUN not supported on this platform")。
// 当 fd > 0 时，通过 os.NewFile(uintptr(fd), "tun") 打开描述符，连接真实 RFC 9484 CONNECT-IP 隧道并调用 CopyCONNECTIPTunnel 驱动双向转发。
func StartTunnel(fd int) error {
	if fd <= 0 {
		return fmt.Errorf("TUN not supported on this platform")
	}
	f := os.NewFile(uintptr(fd), "tun")
	if f == nil {
		return fmt.Errorf("invalid file descriptor: %d", fd)
	}
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessMgr := GetGlobalSessionManager()
	if sessMgr == nil {
		return fmt.Errorf("session manager not initialized")
	}
	ipConn, _, err := sessMgr.DialIP(ctx)
	if err != nil {
		return fmt.Errorf("dial connect-ip: %w", err)
	}
	defer ipConn.Close()

	return CopyCONNECTIPTunnel(ctx, f, ipConn)
}

// StartTunnelWithConn 允许使用指定的底层 IP 传输流驱动移动端 TUN 转发
func StartTunnelWithConn(ctx context.Context, fd int, ipConn io.ReadWriteCloser) error {
	if fd <= 0 {
		return fmt.Errorf("TUN not supported on this platform")
	}
	f := os.NewFile(uintptr(fd), "tun")
	if f == nil {
		return fmt.Errorf("invalid file descriptor: %d", fd)
	}
	defer f.Close()
	return CopyTunnel(ctx, f, ipConn)
}

// OpenTunDevice 移动端占位
func OpenTunDevice(name string, mtu int) (TunDevice, error) {
	return nil, fmt.Errorf("TUN not supported on this platform")
}

// SetInterfaceMTU 移动端占位
func SetInterfaceMTU(devName string, mtu int) error {
	return fmt.Errorf("TUN not supported on this platform")
}

// SetupRoutes 明确返回不支持错误，阻断桌面版 TUN 流程
func SetupRoutes(devName, ipv4 string) error {
	return fmt.Errorf("TUN not supported on this platform")
}

// TeardownRoutes 移动端占位
func TeardownRoutes(devName string) {}

// ProtectHostRoute 移动端占位
func ProtectHostRoute(hostIP string) error { return nil }

// UnprotectHostRoute 移动端占位
func UnprotectHostRoute(hostIP string) {}

// PhysicalDefaultGateway 移动端占位
func PhysicalDefaultGateway() (gw, ifIndex string, err error) {
	return "", "", fmt.Errorf("TUN not supported on this platform")
}

// DialPhysicalDirect 移动端占位
func DialPhysicalDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	if hook := getPhysicalDialerHook(); hook != nil {
		return hook(ctx, network, addr)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

// ListenPhysicalPacket 移动端占位
func ListenPhysicalPacket(ctx context.Context, network string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, ":0")
}

func invalidateGatewayCache() {}

// CleanAero0StaleRoutes 移动端占位
func CleanAero0StaleRoutes() {}

// DetectThirdPartyTUN 移动端第三方 TUN 检测 (扫描 Android VpnService tun0 与 Fake-IP)
func DetectThirdPartyTUN() (bool, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, "", nil
	}
	for _, ifi := range ifaces {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
			continue
		}
		nameLower := strings.ToLower(ifi.Name)
		if strings.HasPrefix(nameLower, "tun") || strings.HasPrefix(nameLower, "ppp") ||
			strings.HasPrefix(nameLower, "ipsec") || strings.HasPrefix(nameLower, "p2p") {
			return true, ifi.Name, nil
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
	return false, "", nil
}
