//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"os"
	"runtime"
)

// ProcessElevated 报告当前进程是否以 root 权限运行。
func ProcessElevated() bool {
	return os.Geteuid() == 0
}

// HostDescription 返回用于日志的系统描述。
func HostDescription() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}
