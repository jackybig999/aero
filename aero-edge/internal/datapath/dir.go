// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package datapath 统一 Edge 数据目录（与 install.sh 同源）。
package datapath

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDir 默认数据目录（可被 AERO_DATA_DIR 或 -data-dir 覆盖）
// Linux 生产: /var/lib/aero
// 其它/开发: ./aero_data
func DefaultDir() string {
	if d := os.Getenv("AERO_DATA_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "linux" {
		if st, err := os.Stat("/var/lib/aero"); err == nil && st.IsDir() {
			return "/var/lib/aero"
		}
		// 无权限写 /var/lib 时回落本地
		if err := os.MkdirAll("/var/lib/aero", 0o755); err == nil {
			return "/var/lib/aero"
		}
	}
	return "aero_data"
}

// Resolve 优先 explicit，否则 DefaultDir；并确保目录存在
func Resolve(explicit string) (string, error) {
	dir := explicit
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Clean(dir), nil
}

// SubMetaPath sub_meta.json 绝对路径
func SubMetaPath(dir string) string {
	return filepath.Join(dir, "sub_meta.json")
}

// ClientSubPath 安装脚本与 Edge 共用的客户端订阅文件
func ClientSubPath(dir string) string {
	return filepath.Join(dir, "client-sub.json")
}
