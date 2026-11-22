//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025 Aero AI System

package edge

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyConfigReload(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGHUP)
}
