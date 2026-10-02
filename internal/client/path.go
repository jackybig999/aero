// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"os"
	"path/filepath"
	"runtime"
)

// GetDataDir 获取各平台标准数据持久化目录并自动创建
func GetDataDir() string {
	var dir string
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			home, _ := os.UserHomeDir()
			dir = filepath.Join(home, "AppData", "Roaming", "AEROSYS")
		} else {
			dir = filepath.Join(appdata, "AEROSYS")
		}
	case "darwin":
		home, _ := os.UserHomeDir()
		if home == "" {
			home = os.Getenv("HOME")
		}
		dir = filepath.Join(home, "Library", "Application Support", "AEROSYS")
	case "android":
		dir = os.Getenv("AERO_DATA_DIR")
		if dir == "" {
			dir = "./data"
		}
	case "ios":
		home, _ := os.UserHomeDir()
		if home == "" {
			home = os.Getenv("HOME")
		}
		dir = filepath.Join(home, "Documents")
	case "linux":
		dir = "/var/lib/aero"
		// 若无法创建 /var/lib/aero (如非 root 运行)，优雅回退到 ~/.config/aero
		if err := os.MkdirAll(dir, 0755); err != nil {
			home, _ := os.UserHomeDir()
			if home == "" {
				home = os.Getenv("HOME")
			}
			dir = filepath.Join(home, ".config", "aero")
		}
	default:
		home, _ := os.UserHomeDir()
		if home == "" {
			home = os.Getenv("HOME")
		}
		dir = filepath.Join(home, ".config", "aero")
	}

	_ = os.MkdirAll(dir, 0755)
	return dir
}
