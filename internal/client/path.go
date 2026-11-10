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
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		dir = filepath.Join(appdata, "AERO")
		oldDir := filepath.Join(appdata, "AEROSYS")
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if _, errOld := os.Stat(oldDir); errOld == nil {
				_ = os.Rename(oldDir, dir)
			}
		}
	case "darwin":
		home, _ := os.UserHomeDir()
		if home == "" {
			home = os.Getenv("HOME")
		}
		dir = filepath.Join(home, "Library", "Application Support", "AERO")
		oldDir := filepath.Join(home, "Library", "Application Support", "AEROSYS")
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if _, errOld := os.Stat(oldDir); errOld == nil {
				_ = os.Rename(oldDir, dir)
			}
		}
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
