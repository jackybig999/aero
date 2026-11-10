//go:build linux

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"log"

	"golang.org/x/sys/unix"
)

type linuxNetworkMonitor struct {
	watcher *debounceWatcher
	fd      int
}

func newPlatformNetworkMonitor() NetworkMonitor {
	return &linuxNetworkMonitor{
		watcher: newDebounceWatcher(),
	}
}

func (m *linuxNetworkMonitor) Start(onChange func(newGW, ifName string)) {
	m.watcher.start(onChange)

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		log.Printf("[NETMON] Linux netlink socket create failed: %v", err)
		return
	}
	m.fd = fd

	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV4_IFADDR,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		m.fd = 0
		log.Printf("[NETMON] Linux netlink socket bind failed: %v", err)
		return
	}

	go func() {
		buf := make([]byte, 4096)
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

func (m *linuxNetworkMonitor) Stop() {
	if m.fd > 0 {
		_ = unix.Close(m.fd)
		m.fd = 0
	}
	m.watcher.stop()
}
