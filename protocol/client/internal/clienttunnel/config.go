// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package clienttunnel

import (
	"fmt"
	"strings"
)

// Config 统一多端客户端隧道配置（Windows, macOS, iOS, Android 通用）
type Config struct {
	ServerAddress   string            `json:"serverAddress"`             // VPS Edge 地址 host:port 或 ip:port
	Token           string            `json:"token"`                     // 认证 Token
	SNIName         string            `json:"sni"`                       // TLS / ECH SNI 伪装域名
	Fingerprint     string            `json:"fingerprint"`               // 浏览器指纹 (chrome, firefox, safari, standard)
	ECHConfigB64    string            `json:"echConfig,omitempty"`       // Base64 ECH 配置
	SplitEnabled    bool              `json:"splitEnabled"`              // 是否开启智能分流
	SubscriptionURL string            `json:"subscriptionUrl,omitempty"` // 订阅地址（拉取与自愈）
	PreferQUIC      bool              `json:"preferQuic"`                // 是否优先尝试 QUIC
	MTU             int               `json:"mtu"`                       // MTU 大小 (默认 1420)
	DNS             []string          `json:"dns"`                       // DNS 解析服务器列表
	Extra           map[string]string `json:"extra,omitempty"`           // 扩展参数
}

// DefaultConfig 返回多平台默认配置
func DefaultConfig() Config {
	return Config{
		SNIName:      "cdn-aero.com",
		Fingerprint:  "chrome",
		SplitEnabled: true,
		PreferQUIC:   false,
		MTU:          1420,
		DNS:          []string{"223.5.5.5", "8.8.8.8"},
		Extra:        make(map[string]string),
	}
}

// Validate 校验必要参数
func (c *Config) Validate() error {
	c.ServerAddress = strings.TrimSpace(c.ServerAddress)
	c.Token = strings.TrimSpace(c.Token)
	if c.ServerAddress == "" && strings.TrimSpace(c.SubscriptionURL) == "" {
		return fmt.Errorf("serverAddress or subscriptionUrl must be provided")
	}
	if c.MTU <= 0 {
		c.MTU = 1420
	}
	if c.SNIName == "" {
		c.SNIName = "cdn-aero.com"
	}
	if len(c.DNS) == 0 {
		c.DNS = []string{"223.5.5.5", "8.8.8.8"}
	}
	return nil
}
