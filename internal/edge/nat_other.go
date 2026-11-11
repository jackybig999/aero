//go:build !linux

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

// ConfigureGlobalTunnelDevice 非 Linux 平台占位
func ConfigureGlobalTunnelDevice(devName string, ipv4CIDR, ipv6CIDR string, mtu int) error {
	return nil
}

// PrepareHostForTunnel 非 Linux 平台占位（共享 TUN 与 NAT 仅支持 Linux）。
func PrepareHostForTunnel(dataDir, devName string) error { return nil }

// RestoreHost 非 Linux 平台占位。
func RestoreHost(dataDir string) error { return nil }
