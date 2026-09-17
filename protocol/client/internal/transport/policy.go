// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package transport

import "os"

// insecureOverride 为 true 时跳过服务端证书校验（仅开发/自签冒烟）。
// 生产必须：-ca-cert 或系统根 + 合法证书，且不设置 AERO_TLS_INSECURE。
var insecureOverride bool

// SetInsecure 显式允许跳过校验（CLI -insecure 或环境变量）
func SetInsecure(v bool) {
	insecureOverride = v
}

// InsecureAllowed 是否允许 InsecureSkipVerify
func InsecureAllowed() bool {
	if insecureOverride {
		return true
	}
	v := os.Getenv("AERO_TLS_INSECURE")
	return v == "1" || v == "true" || v == "TRUE"
}

// ShouldSkipVerify 构建 TLS 时使用：
//   - 已配置 CA 池 → 永不 skip
//   - 否则仅当 InsecureAllowed() 时 skip
func ShouldSkipVerify() bool {
	if Global != nil {
		return false
	}
	return InsecureAllowed()
}
