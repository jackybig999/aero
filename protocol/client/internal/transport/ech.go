// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package ech 实现 ECH（Encrypted Client Hello）支持。
//
// 架构：
//   - 真 ECH：使用 Go 1.24+ 内置 crypto/tls.EncryptedClientHelloConfigList
//   - 伪 ECH（降级）：TLS 外层 SNI = 伪域名，HTTP/2 :authority = 真实目标
//   - ECH 密钥生成：使用 cloudflare/circl/hpke + kem
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

// Config ECH 配置
type Config struct {
	PublicName    string // 伪 SNI: cdn-aero.com
	RealAuthority string // 真实目标（HTTP/2 :authority）
	EnableRealECH bool   // 是否启用真 ECH
	ECHPublicKey  []byte // 真 ECH 公钥（配置分发）
	KEMID         uint16 // KEM 算法 ID
}

// ECHKeyPair ECH 密钥对（服务端使用）
type ECHKeyPair struct {
	ConfigID   uint8
	PublicName string
	PublicKey  []byte
	PrivateKey []byte
	KEMScheme  kem.Scheme
	HPKESuite  hpke.Suite
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// ECHConfigList 序列化的 ECHConfigList（客户端使用）
type ECHConfigList struct {
	Raw []byte
}

// Base64 返回 base64 编码的配置
func (e *ECHConfigList) Base64() string {
	return base64.URLEncoding.EncodeToString(e.Raw)
}

// GenerateECHKeyPair 生成 ECH 密钥对（服务端）
// 使用 X25519 + AES-128-GCM + SHA256
func GenerateECHKeyPair(publicName string, lifetime time.Duration) (*ECHKeyPair, *ECHConfigList, error) {
	// 选择 KEM 方案：优先 X25519Kyber768，降级到纯 X25519
	var scheme kem.Scheme
	hpkeKEM := hpke.KEM_X25519_HKDF_SHA256
	scheme = schemes.ByName("X25519MLKEM768")
	if scheme == nil {
		scheme = schemes.ByName("Kyber768-X25519")
	}
	if scheme != nil {
		hpkeKEM = hpke.KEM_X25519_KYBER768_DRAFT00
	} else {
		scheme = schemes.ByName("X25519")
	}
	if scheme == nil {
		return nil, nil, fmt.Errorf("no supported KEM scheme available")
	}

	// 生成密钥对
	pubKey, privKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate KEM keypair: %w", err)
	}

	pubKeyBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	privKeyBytes, err := privKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	// HPKE 套件：KEM + KDF + AEAD
	kemID := uint16(hpkeKEM)
	kdfID := uint16(0x0001)  // HKDF-SHA256
	aeadID := uint16(0x0001) // AES-128-GCM

	// 构建 ECHConfigList (draft-ietf-tls-esni-18 格式)
	// ECHConfigList = 2-byte length + ECHConfig[]
	// ECHConfig = 1-byte version(0xFE0D) + 2-byte length + contents
	configID := uint8(1) // 配置 ID

	configContents := buildECHConfigContents(configID, kemID, kdfID, aeadID, pubKeyBytes, publicName)

	configList := make([]byte, 2+len(configContents))
	configList[0] = uint8(len(configContents) >> 8)
	configList[1] = uint8(len(configContents))
	copy(configList[2:], configContents)

	kp := &ECHKeyPair{
		ConfigID:   configID,
		PublicName: publicName,
		PublicKey:  pubKeyBytes,
		PrivateKey: privKeyBytes,
		KEMScheme:  scheme,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(lifetime),
	}

	cl := &ECHConfigList{Raw: configList}
	return kp, cl, nil
}

// buildECHConfigContents 构建单个 ECHConfig 的内容
func buildECHConfigContents(configID uint8, kemID, kdfID, aeadID uint16, publicKey []byte, publicName string) []byte {
	// version = 0xFE0D (draft-18)
	version := []byte{0xFE, 0x0D}

	// contents:
	// - 1 byte: config_id
	// - 2 bytes: kem_id
	// - 2 bytes: public_key length
	// - public_key
	// - 2 bytes: public_name length
	// - public_name
	// - 2 bytes: extensions length (0)

	nameBytes := []byte(publicName)
	contents := make([]byte, 0, 64+len(publicKey)+len(nameBytes))

	contents = append(contents, configID)
	contents = append(contents, uint8(kemID>>8), uint8(kemID))
	contents = append(contents, uint8(len(publicKey)>>8), uint8(len(publicKey)))
	contents = append(contents, publicKey...)
	contents = append(contents, uint8(len(nameBytes)>>8), uint8(len(nameBytes)))
	contents = append(contents, nameBytes...)
	contents = append(contents, 0x00, 0x00) // extensions length = 0

	// version + 2-byte length + contents
	result := make([]byte, 0, 4+len(contents))
	result = append(result, version...)
	result = append(result, uint8(len(contents)>>8), uint8(len(contents)))
	result = append(result, contents...)

	return result
}

// BuildClientConfig 构建标准 TLS 客户端配置（伪 ECH）
// 当全局 CA 池设置时，自动启用服务端证书验证
func BuildECHClientConfig(publicName string) *tls.Config {
	cfg := &tls.Config{
		ServerName:         publicName,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true,
	}
	if pool := RootCAs(); pool != nil {
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false
	}
	return cfg
}

// BuildClientConfigWithECH 尝试真 ECH，失败则降级为伪 ECH
// 当全局 CA 池设置时，自动启用服务端证书验证
func BuildClientConfigWithECH(cfg Config) (*tls.Config, error) {
	if cfg.EnableRealECH && len(cfg.ECHPublicKey) > 0 {
		// 真 ECH：使用 Go 1.24+ 内置支持
		tlsCfg := &tls.Config{
			ServerName:                     cfg.PublicName,
			MinVersion:                     tls.VersionTLS13,
			NextProtos:                     []string{"http/1.1"},
			InsecureSkipVerify:             true,
			EncryptedClientHelloConfigList: cfg.ECHPublicKey,
		}
		if pool := RootCAs(); pool != nil {
			tlsCfg.RootCAs = pool
			tlsCfg.InsecureSkipVerify = false
		}
		return tlsCfg, nil
	}
	// 降级为伪 ECH
	return BuildClientConfig(cfg.PublicName), nil
}

// BuildClientConfigWithECHList 使用 ECHConfigList 构建 TLS 配置
// 当全局 CA 池设置且未显式传入 roots 时，自动使用全局池并启用验证
func BuildClientConfigWithECHList(publicName string, echConfigList []byte, verifyCert bool, roots *x509.CertPool) *tls.Config {
	cfg := &tls.Config{
		ServerName:                     publicName,
		MinVersion:                     tls.VersionTLS13,
		NextProtos:                     []string{"http/1.1"},
		EncryptedClientHelloConfigList: echConfigList,
	}
	if !verifyCert {
		cfg.InsecureSkipVerify = true
	} else if roots != nil {
		cfg.RootCAs = roots
	}
	if pool := RootCAs(); pool != nil && cfg.RootCAs == nil {
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false
	}
	return cfg
}

// ValidateServerName 验证伪 SNI 格式
func validateECHServerName(name string) error {
	if name == "" {
		return fmt.Errorf("public name cannot be empty")
	}
	return nil
}

// IsECHSupported 检查当前 Go 版本是否支持 ECH
func IsECHSupported() bool {
	// Go 1.24+ 支持 EncryptedClientHelloConfigList
	var cfg tls.Config
	_ = cfg.EncryptedClientHelloConfigList
	return true
}
