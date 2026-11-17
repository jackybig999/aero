//go:build !linux

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import "errors"

// ConfigureGlobalTunnelDevice 非 Linux 平台占位
func ConfigureGlobalTunnelDevice(devName string, ipv4CIDR, ipv6CIDR string, mtu int) error {
	return nil
}

// PrepareHostForTunnel 非 Linux 平台占位（共享 TUN 与 NAT 仅支持 Linux）。
func PrepareHostForTunnel(dataDir, devName string) error { return nil }

// RestoreHost 非 Linux 平台占位。
func RestoreHost(dataDir string) error { return nil }

// firewallBackend：CONNECT-IP 出口转发只在 Linux 上实现。
func firewallBackend() (string, error) {
	return "", errors.New("CONNECT-IP egress forwarding is only supported on Linux")
}
