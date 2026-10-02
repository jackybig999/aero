//go:build !windows && !linux && !darwin

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

type stubNetworkMonitor struct{}

func newPlatformNetworkMonitor() NetworkMonitor {
	return &stubNetworkMonitor{}
}

func (m *stubNetworkMonitor) Start(onChange func(newGW, ifName string)) {}
func (m *stubNetworkMonitor) Stop()                                     {}
