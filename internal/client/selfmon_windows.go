//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import "golang.org/x/sys/windows"

// processCPUSeconds 返回本进程累计的 CPU 秒数（内核态 + 用户态）。
func processCPUSeconds() (float64, bool) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return 0, false
	}
	// FILETIME 以 100 纳秒为单位
	ticks := func(f windows.Filetime) float64 {
		return float64(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) / 1e7
	}
	return ticks(kernel) + ticks(user), true
}
