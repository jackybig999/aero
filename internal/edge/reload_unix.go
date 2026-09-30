//go:build unix

// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyConfigReload(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGHUP)
}
