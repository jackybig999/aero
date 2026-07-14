//go:build unix

// Copyright 2025 AERO Protocol Contributors

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyConfigReload(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGHUP)
}
