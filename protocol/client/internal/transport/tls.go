// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package tls 使用 utls 实现 TLS 指纹模仿；证书校验策略由 certloader 统一决策。
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

const (
	FingerprintChrome  = "chrome"
	FingerprintFirefox = "firefox"
	FingerprintSafari  = "safari"
	FingerprintRandom  = "random"
)

// BuildClientConfig 标准库 TLS 1.3 客户端配置
func BuildClientConfig(publicName string) *tls.Config {
	cfg := &tls.Config{
		ServerName: publicName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	applyVerifyPolicy(cfg, publicName)
	return cfg
}

// BuildUTLSConfig uTLS 配置（指纹模仿）
func BuildUTLSConfig(publicName, fingerprint string) *utls.Config {
	cfg := &utls.Config{
		ServerName: publicName,
		MinVersion: utls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	applyVerifyPolicyUTLS(cfg, publicName)
	return cfg
}

func applyVerifyPolicy(cfg *tls.Config, serverName string) {
	if HasPins() {
		// 双轨校验：SPKI 优先，公网标准 CA 兜底，绝不误杀多节点
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = MakeVerifyPeerCertificate(serverName)
		return
	}
	if pool := RootCAs(); pool != nil {
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false
		return
	}
	cfg.InsecureSkipVerify = ShouldSkipVerify()
}

func applyVerifyPolicyUTLS(cfg *utls.Config, serverName string) {
	if HasPins() {
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = MakeVerifyPeerCertificate(serverName)
		return
	}
	if pool := RootCAs(); pool != nil {
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false
		return
	}
	cfg.InsecureSkipVerify = ShouldSkipVerify()
}

// UConnClient 包装 utls.UConn
type UConnClient struct {
	*utls.UConn
}

// NewUConn 创建带指纹的 TLS 连接
func NewUConn(conn net.Conn, config *utls.Config, fingerprint string) (*UConnClient, error) {
	var helloID utls.ClientHelloID
	switch fingerprint {
	case FingerprintChrome:
		helloID = utls.HelloChrome_Auto
	case FingerprintFirefox:
		helloID = utls.HelloFirefox_Auto
	case FingerprintSafari:
		helloID = utls.HelloSafari_Auto
	case FingerprintRandom:
		helloID = utls.HelloRandomized
	default:
		helloID = utls.HelloChrome_Auto
	}
	return &UConnClient{UConn: utls.UClient(conn, config, helloID)}, nil
}

// HandshakeContext 执行握手
func (c *UConnClient) HandshakeContext() error {
	return c.UConn.Handshake()
}

// BuildClientConfigWithVerify 附加 PEM CA
func BuildClientConfigWithVerify(publicName string, caCert []byte) (*tls.Config, error) {
	cfg := BuildClientConfig(publicName)
	if len(caCert) == 0 {
		return cfg, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	cfg.RootCAs = pool
	cfg.InsecureSkipVerify = false
	return cfg, nil
}

// ValidateServerName 校验 SNI 非空
func ValidateServerName(name string) error {
	if name == "" {
		return fmt.Errorf("public name cannot be empty")
	}
	return nil
}
