// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package subscribe 提供 Edge 侧订阅生成与 HTTP 下发。
// JSON 字段与 aero-ech/internal/sub 对齐。
package subscribe

// Document 对外订阅文档
type Document struct {
	Version   string   `json:"version"`
	UserID    string   `json:"userId,omitempty"`
	ExpireAt  int64    `json:"expireAt,omitempty"`
	Signature string   `json:"signature,omitempty"`
	Servers   []Server `json:"servers"`
	CreatedAt int64    `json:"createdAt,omitempty"`
}

// Server 节点条目
type Server struct {
	Name     string   `json:"name"`
	Address  string   `json:"address"`
	Token    string   `json:"token"`
	SNI      string   `json:"sni"`
	Protocol string   `json:"protocol"`
	// PinSPKI leaf SPKI SHA-256 base64；自签/无公网 CA 时客户端用于钉扎
	PinSPKI []string `json:"pin_spki,omitempty"`
}

// Meta 本地持久化
type Meta struct {
	Secret   string   `json:"secret"`
	Document Document `json:"document"`
}
