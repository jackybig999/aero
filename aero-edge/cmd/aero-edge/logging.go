// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import "github.com/aero-protocol/aero-edge/internal/applog"

func applogInit(file, format string) error {
	return applog.Init(applog.Config{
		FilePath: file,
		Format:   format,
	})
}
