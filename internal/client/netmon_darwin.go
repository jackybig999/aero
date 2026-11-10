//go:build darwin

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"log"

	"golang.org/x/sys/unix"
)

type darwinNetworkMonitor struct {
	watcher *debounceWatcher
	fd      int
}

func newPlatformNetworkMonitor() NetworkMonitor {
	return &darwinNetworkMonitor{
		watcher: newDebounceWatcher(),
	}
}

func (m *darwinNetworkMonitor) Start(onChange func(newGW, ifName string)) {
	m.watcher.start(onChange)

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		log.Printf("[NETMON] Darwin PF_ROUTE socket open failed: %v", err)
		return
	}
	m.fd = fd

	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				return
			}
			if n > 0 {
				m.watcher.trigger()
			}
		}
	}()
}

func (m *darwinNetworkMonitor) Stop() {
	if m.fd > 0 {
		_ = unix.Close(m.fd)
		m.fd = 0
	}
	m.watcher.stop()
}
