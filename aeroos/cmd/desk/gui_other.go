//go:build !windows && !darwin

package main

import (
	"log"
	"os"

	"github.com/aero-protocol/aero/aeroos/internal/desk"
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
