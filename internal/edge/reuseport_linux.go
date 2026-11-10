// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build linux

package edge

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setReusePortControl(network, address string, c syscall.RawConn) error {
	var controlErr error
	err := c.Control(func(fd uintptr) {
		// 启用 SO_REUSEPORT 以便内核四元组多核分发；如遇严格容器安全策略限制，平滑降级
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return controlErr
}
