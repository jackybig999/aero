// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package transport 为 aero-edge 提供 ECH（Encrypted Client Hello）服务端支持。
package transport

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

// ECHKeyPair ECH 密钥对
type ECHKeyPair struct {
	Config      []byte
	PrivateKey  []byte
	PublicName  string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	SendAsRetry bool
}

// ECHManager ECH 密钥管理器
type ECHManager struct {
	keys       []ECHKeyPair
	publicName string
}

// NewECHManager 创建 ECH 管理器
func NewECHManager(publicName string) *ECHManager {
	return &ECHManager{
		publicName: publicName,
	}
}

// GenerateKey 生成新的 ECH 密钥对
func (m *ECHManager) GenerateKey() (*ECHKeyPair, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	pubKeyBytes := privKey.PublicKey().Bytes()
	privKeyBytes := privKey.Bytes()

	config := buildECHConfig(pubKeyBytes, m.publicName)

	kp := &ECHKeyPair{
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
	configID := uint8(1)
	kemID := uint16(0x0020) // X25519 (KEM)
	nameBytes := []byte(publicName)

	contents := make([]byte, 0, 64+len(pubKey)+len(nameBytes))
	contents = append(contents, configID)
	contents = append(contents, uint8(kemID>>8), uint8(kemID))
	contents = append(contents, uint8(len(pubKey)>>8), uint8(len(pubKey)))
	contents = append(contents, pubKey...)
	contents = append(contents, uint8(len(nameBytes)>>8), uint8(len(nameBytes)))
	contents = append(contents, nameBytes...)
	contents = append(contents, 0x00, 0x00) // extensions length = 0

	config := make([]byte, 0, 4+len(contents))
	config = append(config, 0xFE, 0x0D) // version
	config = append(config, uint8(len(contents)>>8), uint8(len(contents)))
	config = append(config, contents...)

	configList := make([]byte, 2+len(config))
	configList[0] = uint8(len(config) >> 8)
	configList[1] = uint8(len(config))
	copy(configList[2:], config)

	return configList
}

// TLSKeys 返回 tls.EncryptedClientHelloKey 列表
func (m *ECHManager) TLSKeys() []tls.EncryptedClientHelloKey {
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

// ECHConfigResponse ECH 配置响应
type ECHConfigResponse struct {
	PublicName   string `json:"publicName"`
	ConfigBase64 string `json:"configBase64"`
	ExpiresAt    int64  `json:"expiresAt"`
	Version      string `json:"version"`
}

// Handler HTTP 处理器，提供 /ech-config 端点
func (m *ECHManager) Handler(w http.ResponseWriter, r *http.Request) {
	if len(m.keys) == 0 {
		http.Error(w, "no ECH config available", http.StatusServiceUnavailable)
		return
	}

	kp := m.keys[len(m.keys)-1]

	resp := ECHConfigResponse{
		PublicName:   kp.PublicName,
		ConfigBase64: base64.URLEncoding.EncodeToString(kp.Config),
		ExpiresAt:    kp.ExpiresAt.Unix(),
		Version:      "draft-18",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CleanupExpired 清理过期密钥
func (m *ECHManager) CleanupExpired() {
	now := time.Now()
	var valid []ECHKeyPair
	for _, kp := range m.keys {
		if now.Before(kp.ExpiresAt.Add(24 * time.Hour)) {
			valid = append(valid, kp)
		}
	}
	m.keys = valid
}
