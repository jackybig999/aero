//go:build !windows && !linux && !darwin

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

type stubNetworkMonitor struct{}

func newPlatformNetworkMonitor() NetworkMonitor {
	return &stubNetworkMonitor{}
}

func (m *stubNetworkMonitor) Start(onChange func(newGW, ifName string)) {}
func (m *stubNetworkMonitor) Stop()                                     {}
