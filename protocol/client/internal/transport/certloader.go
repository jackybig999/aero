// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package certloader 提供客户端 CA 证书加载，用于生产环境验证 Edge 服务端身份。
// 未配置时保留默认行为（InsecureSkipVerify=true），保证开发和测试环境兼容性。
package transport

import (
	"crypto/x509"
	"fmt"
	"os"
)

// Global 全局 CA 证书池。当非 nil 时，TLS 构建函数会自动启用服务端证书验证。
var Global *x509.CertPool

// SetGlobal 设置全局 CA 证书池
func SetGlobal(pool *x509.CertPool) {
	Global = pool
}

// LoadCA 从 PEM 文件加载 CA 证书并构建证书池
func LoadCA(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid PEM certificates found in %s", path)
	}
	return pool, nil
}

// RootCAs 返回全局 CA 池（如果已设置），否则返回 nil
func RootCAs() *x509.CertPool {
	return Global
}
