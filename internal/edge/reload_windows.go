//go:build windows

// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import "os"

func notifyConfigReload(ch chan<- os.Signal) {
	_ = ch
}
