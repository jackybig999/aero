// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package ech 为 aero-edge 提供 ECH（Encrypted Client Hello）服务端支持。
//
// Go 1.24+ 的 crypto/tls 内置了 ECH 服务端支持，通过 EncryptedClientHelloKeys 配置。
// 本包负责：
//   - 生成 ECH 密钥对（使用 X25519 KEM，Go 标准库支持）
//   - 提供 /ech-config HTTP 端点供客户端获取配置
//   - 管理密钥轮换和过期
package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// KeyPair ECH 密钥对
type KeyPair struct {
	Config      []byte
	PrivateKey  []byte
	PublicName  string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	SendAsRetry bool
}

// Manager ECH 密钥管理器
type Manager struct {
	keys       []KeyPair
	publicName string
}

// NewManager 创建 ECH 管理器
func NewManager(publicName string) *Manager {
	return &Manager{
		publicName: publicName,
	}
}

// GenerateKey 生成新的 ECH 密钥对
//
// 使用 X25519 KEM (0x0020) + HKDF-SHA256 (0x0001) + AES-128-GCM (0x0001)
// 这是 Go 1.24 ECH 实现支持的标准组合。
func (m *Manager) GenerateKey() (*KeyPair, error) {
	// 生成 X25519 密钥对
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	pubKeyBytes := privKey.PublicKey().Bytes()
	privKeyBytes := privKey.Bytes()

	// 构建 ECHConfig (draft-ietf-tls-esni-18 格式)
	// version = 0xFE0D
	// kem_id = 0x0020 (X25519)
	// kdf_id = 0x0001 (HKDF-SHA256)
	// aead_id = 0x0001 (AES-128-GCM)
	config := buildECHConfig(pubKeyBytes, m.publicName)

	kp := &KeyPair{
		Config:      config,
		PrivateKey:  privKeyBytes,
		PublicName:  m.publicName,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
		SendAsRetry: true,
	}

	m.keys = append(m.keys, *kp)
	return kp, nil
}

// buildECHConfig 构建 ECHConfig 二进制数据
func buildECHConfig(pubKey []byte, publicName string) []byte {
	// ECHConfig 格式：
	// - 2 bytes: version (0xFE0D)
	// - 2 bytes: length
	// - 1 byte: config_id
	// - 2 bytes: kem_id (0x0020 = X25519)
	// - 2 bytes: public_key length
	// - public_key
	// - 2 bytes: public_name length
	// - public_name
	// - 2 bytes: extensions length (0)

	configID := uint8(1)
	kemID := uint16(0x0020) // X25519 (KEM)
	// KDF: HKDF-SHA256 (0x0001), AEAD: AES-128-GCM (0x0001)
	nameBytes := []byte(publicName)

	// contents
	contents := make([]byte, 0, 64+len(pubKey)+len(nameBytes))
	contents = append(contents, configID)
	contents = append(contents, uint8(kemID>>8), uint8(kemID))
	contents = append(contents, uint8(len(pubKey)>>8), uint8(len(pubKey)))
	contents = append(contents, pubKey...)
	contents = append(contents, uint8(len(nameBytes)>>8), uint8(len(nameBytes)))
	contents = append(contents, nameBytes...)
	contents = append(contents, 0x00, 0x00) // extensions length = 0

	// ECHConfig: version + length + contents
	config := make([]byte, 0, 4+len(contents))
	config = append(config, 0xFE, 0x0D) // version
	config = append(config, uint8(len(contents)>>8), uint8(len(contents)))
	config = append(config, contents...)

	// ECHConfigList: 2-byte length + config
	configList := make([]byte, 2+len(config))
	configList[0] = uint8(len(config) >> 8)
	configList[1] = uint8(len(config))
	copy(configList[2:], config)

	return configList
}

// TLSKeys 返回 tls.EncryptedClientHelloKey 列表
func (m *Manager) TLSKeys() []tls.EncryptedClientHelloKey {
	var keys []tls.EncryptedClientHelloKey
	for _, kp := range m.keys {
		if time.Now().Before(kp.ExpiresAt) {
			keys = append(keys, tls.EncryptedClientHelloKey{
				Config:      kp.Config,
				PrivateKey:  kp.PrivateKey,
				SendAsRetry: kp.SendAsRetry,
			})
		}
	}
	return keys
}

// ConfigResponse ECH 配置响应
type ConfigResponse struct {
	PublicName    string `json:"publicName"`
	ConfigBase64  string `json:"configBase64"`
	ExpiresAt     int64  `json:"expiresAt"`
	Version       string `json:"version"`
}

// Handler HTTP 处理器，提供 /ech-config 端点
func (m *Manager) Handler(w http.ResponseWriter, r *http.Request) {
	if len(m.keys) == 0 {
		http.Error(w, "no ECH config available", http.StatusServiceUnavailable)
		return
	}

	// 使用最新的密钥
	kp := m.keys[len(m.keys)-1]

	resp := ConfigResponse{
		PublicName:   kp.PublicName,
		ConfigBase64: base64.URLEncoding.EncodeToString(kp.Config),
		ExpiresAt:    kp.ExpiresAt.Unix(),
		Version:      "draft-18",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CleanupExpired 清理过期密钥
func (m *Manager) CleanupExpired() {
	now := time.Now()
	var valid []KeyPair
	for _, kp := range m.keys {
		if now.Before(kp.ExpiresAt.Add(24 * time.Hour)) {
			valid = append(valid, kp)
		}
	}
	m.keys = valid
}
