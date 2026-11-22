// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

//go:build !windows

package main

import (
	"syscall"
)

func raiseFileLimits() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		if rLimit.Cur < 1048576 {
			rLimit.Cur = 1048576
			if rLimit.Max < 1048576 {
				rLimit.Max = 1048576
			}
			_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		}
	}
}
