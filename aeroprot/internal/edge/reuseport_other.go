// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build !linux

package edge

import "syscall"

func setReusePortControl(network, address string, c syscall.RawConn) error {
	return nil
}
