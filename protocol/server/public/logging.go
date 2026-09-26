// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

func applogInit(file, format string) error {
	return InitAppLog(AppLogConfig{
		FilePath: file,
		Format:   format,
	})
}
