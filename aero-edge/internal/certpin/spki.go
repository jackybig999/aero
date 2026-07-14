// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package certpin 从 TLS 证书提取 SPKI SHA-256（base64）用于订阅钉扎。
package certpin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// FromTLS 计算 leaf 证书 SubjectPublicKeyInfo 的 SHA-256 pin
func FromTLS(cert *tls.Certificate) (string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", fmt.Errorf("empty certificate")
	}
	return FromDER(cert.Certificate[0])
}

// FromDER 从 DER 证书字节计算 pin
func FromDER(der []byte) (string, error) {
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// FromPEM 从 PEM 证书计算 pin
func FromPEM(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("no PEM certificate")
	}
	return FromDER(block.Bytes)
}
