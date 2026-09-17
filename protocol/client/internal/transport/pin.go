// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package transport

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// pins 允许的 SPKI SHA-256（base64 std）
var pins []string

// SetPins 设置证书钉扎；非空时 TLS 用自定义校验
func SetPins(p []string) {
	pins = append([]string(nil), p...)
}

// Pins 当前钉扎列表
func Pins() []string {
	return append([]string(nil), pins...)
}

// HasPins 是否配置了钉扎
func HasPins() bool {
	return len(pins) > 0
}

// MatchSPKI 检查证书是否匹配任一 pin
func MatchSPKI(cert *x509.Certificate) bool {
	if cert == nil || len(pins) == 0 {
		return false
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	got := base64.StdEncoding.EncodeToString(sum[:])
	for _, p := range pins {
		if p == got {
			return true
		}
	}
	return false
}

// VerifyPeerCertificate 供 crypto/tls.Config.VerifyPeerCertificate 使用
func VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(pins) == 0 {
		return nil
	}
	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificates")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	if !MatchSPKI(cert) {
		return fmt.Errorf("certificate SPKI pin mismatch")
	}
	return nil
}
