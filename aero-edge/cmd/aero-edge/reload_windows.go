//go:build windows

// Copyright 2025 AERO Protocol Contributors

package main

import "os"

// Windows 无 SIGHUP；用 POST /admin/reload。
func notifyConfigReload(ch chan<- os.Signal) {
	_ = ch
}
