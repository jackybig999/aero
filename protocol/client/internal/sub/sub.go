// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package sub 实现订阅解析和验证。
package sub

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Subscription YAML/JSON 订阅格式
type Subscription struct {
	Version          string         `json:"version" yaml:"ver"`
	UserID           string         `json:"userId,omitempty" yaml:"user_id"`
	Slug             string         `json:"slug,omitempty" yaml:"slug"`
	SubTicketSeed    string         `json:"subTicketSeed,omitempty" yaml:"sub_ticket_seed"`
	ProtocolPriority []string       `json:"protocolPriority,omitempty" yaml:"protocol_priority"`
	ExpireAt         int64          `json:"expireAt,omitempty" yaml:"expire_at"`
	SwitchStatus     string         `json:"switchStatus,omitempty" yaml:"switch_status"`
	Signature        string         `json:"signature,omitempty" yaml:"sig"`
	Servers          []ServerConfig `json:"servers" yaml:"nodes"`
	CreatedAt        int64          `json:"createdAt,omitempty" yaml:"created_at"`
	Opt              Optimization   `json:"optimization,omitempty" yaml:"optimization"`
}

type ServerConfig struct {
	Name     string `json:"name" yaml:"name"`
	Address  string `json:"address" yaml:"addr"`
	Token    string `json:"token" yaml:"token"`
	SNI      string `json:"sni" yaml:"sni"`
	Protocol string `json:"protocol" yaml:"protocol"`
	// PinSPKI leaf SPKI SHA-256 base64（与 Edge subscribe 字段一致）
	PinSPKI []string `json:"pin_spki,omitempty" yaml:"pin_spki"`
}

type Optimization struct {
	AINodes    []string `json:"aiNodes" yaml:"ai_nodes"`
	GameNodes  []string `json:"gameNodes" yaml:"game_nodes"`
	DefaultQoS string   `json:"defaultQoS" yaml:"default_qos"`
	Bandwidth  string   `json:"bandwidth" yaml:"bandwidth_limit"`
}

// IsExpired 检查订阅是否过期或已被管理员关闭
func (s *Subscription) IsExpired() bool {
	if s.SwitchStatus == "off" {
		return true
	}
	if s.ExpireAt <= 0 {
		return false
	}
	return time.Now().Unix() > s.ExpireAt
}

// ParseBase64 解析 base64 编码的订阅
func ParseBase64(encoded string) (*Subscription, error) {
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	var sub Subscription
	if err := json.Unmarshal(decoded, &sub); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return &sub, nil
}

// ToBase64 序列化为 base64
func (s *Subscription) ToBase64() (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(data), nil
}

// DeriveNodeToken 基于用户种子和目标域名派生单节点动态访问 Token
func DeriveNodeToken(seed, domain string) string {
	if seed == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(seed + ":" + strings.ToLower(strings.TrimSpace(domain))))
	return "tok_" + hex.EncodeToString(h.Sum(nil))[:24]
}
