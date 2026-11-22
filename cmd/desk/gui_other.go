//go:build !windows && !darwin

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"log"
	"os"

	"github.com/aero-protocol/aero/internal/desk"
)

func ensureSingleInstance() bool {
	return true
}

func selectDirectoryDialog() string {
	return os.Getenv("HOME")
}

func runDesktopWindow(deps *desk.IPCDependencies, netDaemon *desk.ClientDaemon) {
	log.Fatalf("AERO OS 桌面工作台仅支持 Windows 与 macOS 平台运行 (headless platform not supported)")
}
