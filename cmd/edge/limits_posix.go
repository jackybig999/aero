// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

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
