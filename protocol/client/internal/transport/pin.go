// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package transport

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	pinsMu  sync.RWMutex
	pinsSet = make(map[string]struct{})
)

// SetPins 设置证书钉扎；非空时 TLS 用自定义校验
func SetPins(p []string) {
	pinsMu.Lock()
	defer pinsMu.Unlock()
	pinsSet = make(map[string]struct{})
	for _, pin := range p {
		pin = strings.TrimSpace(pin)
		if pin != "" {
			pinsSet[pin] = struct{}{}
		}
	}
}

// AddPins 添加更多有效 SPKI 钉扎（支持多节点多证书共存）
func AddPins(p ...string) {
	pinsMu.Lock()
	defer pinsMu.Unlock()
	for _, pin := range p {
		pin = strings.TrimSpace(pin)
		if pin != "" {
			pinsSet[pin] = struct{}{}
		}
	}
}

// ClearPins 清空全部证书钉扎
func ClearPins() {
	pinsMu.Lock()
	defer pinsMu.Unlock()
	pinsSet = make(map[string]struct{})
}

// Pins 当前钉扎列表
func Pins() []string {
	pinsMu.RLock()
	defer pinsMu.RUnlock()
	list := make([]string, 0, len(pinsSet))
	for p := range pinsSet {
		list = append(list, p)
	}
	return list
}

// HasPins 是否配置了钉扎
func HasPins() bool {
	pinsMu.RLock()
	defer pinsMu.RUnlock()
	return len(pinsSet) > 0
}

// CertSPKI 计算证书 RawSubjectPublicKeyInfo 的 SHA-256 Base64 字符串
func CertSPKI(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// MatchSPKI 检查证书是否匹配任一 pin
func MatchSPKI(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	pinsMu.RLock()
	defer pinsMu.RUnlock()
	if len(pinsSet) == 0 {
		return false
	}
	got := CertSPKI(cert)
	_, ok := pinsSet[got]
	return ok
}

// MakeVerifyPeerCertificate 构造双轨校验器：
// 1. 若证书匹配 SPKI 钉扎 -> 直接信任通过；
// 2. 若证书公钥未命中钉扎（多节点/老节点/自签切换）-> 优雅回退至系统信任根链 (Let's Encrypt / ZeroSSL 等正规 CA) 校验；
// 3. 只有两者皆失败且未指定跳过校验时，才拒绝握手。彻底消除“换 VPS 误报 SPKI Mismatch”问题！
func MakeVerifyPeerCertificate(serverName string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			if ShouldSkipVerify() {
				return nil
			}
			return fmt.Errorf("no peer certificates presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer certificate: %w", err)
		}

		// 轨道 1：SPKI 钉扎校验
		if MatchSPKI(cert) {
			return nil
		}

		// 轨道 2：系统公网根证书校验 (System Root CAs Fallback)
		opts := x509.VerifyOptions{
			DNSName:     serverName,
			Roots:       RootCAs(), // nil 表示使用操作系统受信任根证书库
			CurrentTime: time.Now(),
		}
		if len(rawCerts) > 1 {
			opts.Intermediates = x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if inter, err := x509.ParseCertificate(raw); err == nil {
					opts.Intermediates.AddCert(inter)
				}
			}
		}
		if _, err := cert.Verify(opts); err == nil {
			return nil
		}

		// 轨道 3：调试/开发跳过开关
		if ShouldSkipVerify() {
			return nil
		}

		return fmt.Errorf("tls verify failed: neither SPKI pin nor trusted CA matched for %s", serverName)
	}
}

// VerifyPeerCertificate 兼容旧调用的缺省实现
func VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return MakeVerifyPeerCertificate("")(rawCerts, verifiedChains)
}
