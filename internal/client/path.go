// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"os"
	"path/filepath"
	"runtime"
)

// GetDataDir 获取各平台标准数据持久化目录并自动创建。AERO_DATA_DIR 在所有平台上优先。
func GetDataDir() string {
	var dir string
	if env := os.Getenv("AERO_DATA_DIR"); env != "" && runtime.GOOS != "android" {
		_ = os.MkdirAll(env, 0o700)
		return env
	}
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
		// 不能用 /var/lib/aero：那是 edge 的数据目录，客户端会覆盖其中同名的 geodata_direct.txt。
		dir = linuxClientDir
		migrateLinuxClientDir(legacyLinuxDir, dir)
		// 无法创建（如非 root 运行）时回退到 ~/.config/aero
		if err := os.MkdirAll(dir, 0o755); err != nil {
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

const (
	linuxClientDir = "/var/lib/aero-client"
	legacyLinuxDir = "/var/lib/aero"
)

// migrateLinuxClientDir 把旧版客户端写在 /var/lib/aero 的客户端专属配置搬到新目录。
// 旧目录同时是 edge 数据目录（有 edge.lock）时不动它；geodata 会重新下载，不搬。
func migrateLinuxClientDir(oldDir, newDir string) {
	if _, err := os.Stat(newDir); err == nil {
		return
	}
	if _, err := os.Stat(filepath.Join(oldDir, "edge.lock")); err == nil {
		return
	}
	for _, name := range []string{"chain_proxy.json", "sni_profile.json"} {
		src := filepath.Join(oldDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.MkdirAll(newDir, 0o755); err != nil {
			return
		}
		_ = os.Rename(src, filepath.Join(newDir, name))
	}
}
