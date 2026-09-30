//go:build windows

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsNetworkMonitor struct {
	watcher *debounceWatcher
	handle  windows.Handle
}

func newPlatformNetworkMonitor() NetworkMonitor {
	return &windowsNetworkMonitor{
		watcher: newDebounceWatcher(),
	}
}

func (m *windowsNetworkMonitor) Start(onChange func(newGW, ifName string)) {
	m.watcher.start(onChange)

	cb := windows.NewCallback(func(callerContext uintptr, row uintptr, notificationType uintptr) uintptr {
		m.watcher.trigger()
		return 0
	})

	var handle windows.Handle
	err := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, cb, unsafe.Pointer(nil), false, &handle)
	if err != nil {
		log.Printf("[NETMON] Windows NotifyIpInterfaceChange failed: %v", err)
		return
	}
	m.handle = handle
}

func (m *windowsNetworkMonitor) Stop() {
	if m.handle != 0 {
		_ = windows.CancelMibChangeNotify2(m.handle)
		m.handle = 0
	}
	m.watcher.stop()
}
