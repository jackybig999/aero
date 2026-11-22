//go:build darwin

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"log"
	"os"
	"os/exec"

	"github.com/aero-protocol/aero/internal/desk"
)

type noopBinder struct{}

func (n *noopBinder) Bind(name string, f interface{}) error { return nil }

func ensureSingleInstance() bool {
	return true
}

func selectDirectoryDialog() string {
	home, err := os.UserHomeDir()
	if err == nil {
		return home
	}
	return os.Getenv("HOME")
}

func runDesktopWindow(deps *desk.IPCDependencies, netDaemon *desk.ClientDaemon) {
	log.Printf("[AERO OS] 启动 macOS 桌面模式")
	desk.RegisterAll(&noopBinder{}, deps)
	_ = exec.Command("open", "http://127.0.0.1:55555").Start()
	select {}
}
