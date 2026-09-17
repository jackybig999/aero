// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package android is the VpnService-side of the same engine as Windows aeroapp.
//
// Do not fork aero-ech. Kotlin VpnService captures packets; Go (this module)
// does split, CONNECT, and gVisor — same packages iOS and Win use.
package android

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aero-protocol/aero-ech/internal/clienttunnel"
	"github.com/aero-protocol/aero-ech/internal/tun"
)

// TunnelConfig is the unified config used across all platforms.
type TunnelConfig = clienttunnel.Config

var (
	mu             sync.Mutex
	activeEngine   *clienttunnel.Engine
	packetCallback func([]byte)
)

// RegisterPacketCallback registers the Kotlin packet consumer callback
// for the memory injection mode.
func RegisterPacketCallback(cb func([]byte)) {
	mu.Lock()
	packetCallback = cb
	mu.Unlock()
}

// StartJSON starts the Go tunnel from Kotlin using memory injection mode.
func StartJSON(configJSON string) error {
	var cfg TunnelConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if activeEngine != nil && activeEngine.IsRunning() {
		return fmt.Errorf("tunnel already running")
	}

	eng, err := clienttunnel.NewEngine(cfg)
	if err != nil {
		return fmt.Errorf("init engine: %w", err)
	}

	onOut := func(pkt []byte) {
		mu.Lock()
		cb := packetCallback
		mu.Unlock()
		if cb != nil {
			cb(pkt)
		}
	}

	if err := eng.StartPacketTunnel(onOut); err != nil {
		return fmt.Errorf("start packet tunnel: %w", err)
	}

	activeEngine = eng
	return nil
}

// StartFD starts the Go tunnel directly attaching the Android VpnService file descriptor (zero-copy mode).
func StartFD(fd int, configJSON string) error {
	var cfg TunnelConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if activeEngine != nil && activeEngine.IsRunning() {
		return fmt.Errorf("tunnel already running")
	}

	dev, err := tun.NewDeviceFromFD(fd, cfg.MTU)
	if err != nil {
		return fmt.Errorf("attach tun fd: %w", err)
	}

	eng, err := clienttunnel.NewEngine(cfg)
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("init engine: %w", err)
	}

	if err := eng.StartWithDevice(dev); err != nil {
		return fmt.Errorf("start with dev: %w", err)
	}

	activeEngine = eng
	return nil
}

// Stop stops the active tunnel engine.
func Stop() {
	mu.Lock()
	eng := activeEngine
	activeEngine = nil
	mu.Unlock()

	if eng != nil {
		eng.Stop()
	}
}

// HandlePacket injects one IP packet from VpnService.FileInputStream.
func HandlePacket(pkt []byte) error {
	mu.Lock()
	eng := activeEngine
	mu.Unlock()

	if eng == nil || !eng.IsRunning() {
		return fmt.Errorf("tunnel not running")
	}
	return eng.HandlePacket(pkt)
}

// IsRunning reports whether the Go tunnel engine is running.
func IsRunning() bool {
	mu.Lock()
	eng := activeEngine
	mu.Unlock()
	return eng != nil && eng.IsRunning()
}

// Stats returns the real-time tunnel stats as a JSON string.
func Stats() string {
	mu.Lock()
	eng := activeEngine
	mu.Unlock()

	if eng == nil {
		return `{"isRunning":false}`
	}
	data, _ := json.Marshal(eng.Stats())
	return string(data)
}

// ProtectHint documents the Win-equivalent call Kotlin must make.
func ProtectHint() string {
	return "VpnService.protect(edgeTcpFd) == tun.ProtectHostRoute"
}

// NetworkChanged handles mobile Wi-Fi/cellular network handovers.
func NetworkChanged(ctx context.Context, physicalIP string) {
	_ = ctx
	_ = physicalIP
}
