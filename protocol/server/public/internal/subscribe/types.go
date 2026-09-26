// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package subscribe 提供 Edge 侧订阅生成与 HTTP 下发。
// JSON 字段与 aero-ech/internal/sub 对齐。
package subscribe

import "time"

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
	Name     string `json:"name"`
	Address  string `json:"address"`
	Token    string `json:"token"`
	SNI      string `json:"sni"`
	Protocol string `json:"protocol"`
	// PinSPKI leaf SPKI SHA-256 base64；自签/无公网 CA 时客户端用于钉扎
	PinSPKI []string `json:"pin_spki,omitempty"`
}

// UserSub 用户专属订阅结构 (格式: /sub/{username}{6位随机码})
type UserSub struct {
	Username  string   `json:"username"`
	Slug      string   `json:"slug"`      // 专属 slug，如 jacky888abc
	Token     string   `json:"token"`     // 用户专属连接 Token
	ExpireAt  int64    `json:"expireAt"`  // 过期时间戳 (unix 秒)
	Servers   []Server `json:"servers"`   // 分配给该用户的多 VPS 节点列表
	Signature string   `json:"signature"` // 校验签名
	CreatedAt int64    `json:"createdAt"` // 创建时间戳
}

// IsExpired 判断用户订阅是否已到期
func (u *UserSub) IsExpired() bool {
	if u.ExpireAt <= 0 {
		return false
	}
	return time.Now().Unix() > u.ExpireAt
}

// Meta 本地持久化 (保持 secret 和 document 字段 100% 兼容老单节点格式)
type Meta struct {
	Secret   string             `json:"secret"`
	Document Document           `json:"document"`
	UserSubs map[string]UserSub `json:"user_subs,omitempty"`
}
