// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build !windows

package public

import "github.com/aero-protocol/aero-ech/internal/tun"

// StartPlatformMonitor: Win uses NotifyIpInterfaceChange; mac/Linux/iOS poll
// PhysicalIfaceIPv4 every checkInterval (same detect() path as Windows backup).
func (m *Monitor) StartPlatformMonitor() {}

func platformDefaultSource() string {
	if ip := tun.PhysicalIfaceIPv4(); ip != nil {
		return ip.String()
	}
	return ""
}
