//go:build android

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"fmt"
	"net"
)

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
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

// ListenPhysicalPacket 移动端占位
func ListenPhysicalPacket(ctx context.Context, network string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, ":0")
}

func invalidateGatewayCache() {}
