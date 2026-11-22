//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025 Aero AI System

package edge

import "os"

func notifyConfigReload(ch chan<- os.Signal) {
	_ = ch
}
