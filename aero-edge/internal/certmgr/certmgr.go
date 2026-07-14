// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package certmgr 提供证书管理，支持自签名、手动证书和 Let's Encrypt 自动证书。
package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Source 证书来源
type Source int

const (
	SelfSigned Source = iota
	Manual
	LetsEncrypt
)

// Manager 证书管理器
type Manager struct {
	mu          sync.RWMutex
	source      Source
	certFile    string
	keyFile     string
	domains     []string
	cacheDir    string
	email       string
	cert        *tls.Certificate
	autocertMgr *autocert.Manager // Let's Encrypt 专用
}

// Config 证书管理器配置
type Config struct {
	Source   Source
	CertFile string
	KeyFile  string
	Domains  []string
	CacheDir string
	Email    string
}

// NewManager 创建证书管理器
func NewManager(cfg Config) (*Manager, error) {
	m := &Manager{
		source:   cfg.Source,
		certFile: cfg.CertFile,
		keyFile:  cfg.KeyFile,
		domains:  cfg.Domains,
		cacheDir: cfg.CacheDir,
		email:    cfg.Email,
	}

	switch cfg.Source {
	case SelfSigned:
		cert, err := generateSelfSigned(cfg.Domains)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		m.cert = cert
		log.Printf("[CERT] Self-signed certificate for %v", cfg.Domains)

	case Manual:
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, fmt.Errorf("manual cert requires -cert and -key")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		m.cert = &cert
		log.Printf("[CERT] Loaded certificate from %s", cfg.CertFile)

	case LetsEncrypt:
		if len(cfg.Domains) == 0 {
			return nil, fmt.Errorf("letsencrypt requires at least one domain")
		}
		if cfg.CacheDir == "" {
			cfg.CacheDir = "./certs"
		}
		if err := os.MkdirAll(cfg.CacheDir, 0750); err != nil {
			return nil, fmt.Errorf("create cert cache dir: %w", err)
		}
		m.autocertMgr = &autocert.Manager{
			Cache:      autocert.DirCache(cfg.CacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domains...),
			Email:      cfg.Email,
		}
		log.Printf("[CERT] Let's Encrypt configured for %v (cache=%s)", cfg.Domains, cfg.CacheDir)
	}

	return m, nil
}

// GetCertificate 返回 TLS 证书（tls.Config.GetCertificate 回调）
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Let's Encrypt 模式：委托给 autocert（自动处理获取和续期）
	if m.autocertMgr != nil {
		return m.autocertMgr.GetCertificate(hello)
	}

	m.mu.RLock()
	cert := m.cert
	m.mu.RUnlock()

	if cert == nil {
		return nil, fmt.Errorf("no certificate available")
	}
	return cert, nil
}

// ACMEHandler 返回 ACME HTTP-01 挑战处理器（用于挂载到 :80 端口）
// 返回 nil 表示未启用 Let's Encrypt 或不需要外部 handler
func (m *Manager) ACMEHandler() http.Handler {
	if m.autocertMgr != nil {
		return m.autocertMgr.HTTPHandler(nil)
	}
	return nil
}

// TLSConfig 返回完整的 TLS 配置
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
		GetCertificate:     m.GetCertificate,
		InsecureSkipVerify: false,
	}
}

// Certificate 返回当前证书
func (m *Manager) Certificate() *tls.Certificate {
	return m.cert
}

// shouldRenew 检查证书是否需要续期（30 天内过期）
// 注意：Let's Encrypt 模式下由 autocert 内部自动续期，此函数仅用于手动/自签名证书
func (m *Manager) shouldRenew() bool {
	if m.autocertMgr != nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil || len(m.cert.Certificate) == 0 {
		return true
	}
	cert, err := x509.ParseCertificate(m.cert.Certificate[0])
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < 30*24*time.Hour
}

// generateSelfSigned 生成自签名证书
func generateSelfSigned(domains []string) (*tls.Certificate, error) {
	if len(domains) == 0 {
		domains = []string{"localhost", "cdn-aero.com"}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"AERO Protocol"},
			CommonName:   domains[0],
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domains,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf("create self-signed cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load self-signed cert: %w", err)
	}
	return &cert, nil
}

// SaveToDisk 将证书保存到磁盘
// 注意：Let's Encrypt 证书由 autocert 自动缓存到 CacheDir，无需手动保存
func (m *Manager) SaveToDisk(certPath, keyPath string) error {
	if m.autocertMgr != nil {
		return fmt.Errorf("let's encrypt certificates are managed by autocert, use CacheDir instead")
	}
	if m.cert == nil || len(m.cert.Certificate) == 0 {
		return fmt.Errorf("no certificate to save")
	}

	certDER := m.cert.Certificate[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}

	// 私钥提取需要类型断言，当前简化处理
	_ = keyPath
	return fmt.Errorf("SaveToDisk: private key extraction not implemented for non-autocert certs")
}
