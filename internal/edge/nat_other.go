//go:build !linux

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

// ConfigureGlobalTunnelDevice 非 Linux 平台占位
func ConfigureGlobalTunnelDevice(devName string, ipv4CIDR, ipv6CIDR string, mtu int) error {
	return nil
}

// EnableKernelForwarding 非 Linux 平台占位
func EnableKernelForwarding() error {
	return nil
}

// ApplyEdgeFirewall 非 Linux 平台占位
func ApplyEdgeFirewall(devName string) error {
	return nil
}

// CleanupEdgeFirewall 非 Linux 平台占位
func CleanupEdgeFirewall(devName string) {}
