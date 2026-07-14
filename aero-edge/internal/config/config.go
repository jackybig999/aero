// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package config

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	TLSPorts       []int    // TLS 端口（443, 8443）
	PlainPorts     []int    // Plain HTTP 端口（80）
	QUICPorts      []int    // QUIC 端口（预留）
	CertFile       string
	KeyFile        string
	TLSCert        *tls.Certificate
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error) // Let's Encrypt 动态证书
}

// ParsePorts 解析逗号分隔的端口列表
func ParsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			continue
		}
		if port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	return ports
}

// ClassifyPorts 根据端口分类：443/8443=TLS, 80=Plain, 4443/3443/4433=QUIC, 其他=TLS
func ClassifyPorts(ports []int) (tls, plain, quic []int) {
	for _, p := range ports {
		switch p {
		case 443, 8443:
			tls = append(tls, p)
		case 80:
			plain = append(plain, p)
		case 4443, 3443, 4433:
			quic = append(quic, p)
		default:
			// 其他端口默认 TLS
			tls = append(tls, p)
		}
	}
	return
}
