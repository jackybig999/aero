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
	"net"
	"net/http"
	"os"
	"strings"
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
	mu             sync.RWMutex
	source         Source
	certFile       string
	keyFile        string
	domains        []string
	cacheDir       string
	email          string
	cert           *tls.Certificate
	lastPublicCert *tls.Certificate // last successful LE/public cert (prefer over self-signed)
	autocertMgr    *autocert.Manager // Let's Encrypt 专用
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
//
// Let's Encrypt / autocert 在「无 SNI」或「SNI=IP」时会返回
// missing server name / missing certificate，导致本机探测、IP 访问、
// 部分客户端握手直接失败。此处做兼容：
//  1. 空 SNI → 用配置的主域名再向 autocert 取证（服务已缓存的 LE 证书）
//  2. autocert 仍失败 → 回退自签名应急证书（运维/Admin 可用；正式客户端应走域名 SNI）
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.autocertMgr != nil {
		h := hello
		sni := ""
		if h != nil {
			sni = h.ServerName
		}
		// Empty / IP SNI: only for admin loopback — self-signed is OK.
		// Public domain SNI: NEVER prefer self-signed over a previously good LE cert.
		emptySNI := sni == "" || net.ParseIP(sni) != nil
		if emptySNI && len(m.domains) > 0 {
			cp := *h
			cp.ServerName = m.domains[0]
			h = &cp
			sni = m.domains[0]
			emptySNI = false
		}

		m.mu.RLock()
		lastGood := m.lastPublicCert
		m.mu.RUnlock()

		// Fast path: serve last good public cert while refresh continues in background.
		if lastGood != nil && !emptySNI {
			go m.refreshPublicCert(h)
			return lastGood, nil
		}

		type result struct {
			cert *tls.Certificate
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			c, e := m.autocertMgr.GetCertificate(h)
			ch <- result{c, e}
		}()
		// First connection may need ACME; allow more time than 2.5s.
		timeout := 8 * time.Second
		if lastGood != nil {
			timeout = 2 * time.Second
		}
		select {
		case r := <-ch:
			if r.err == nil && r.cert != nil {
				m.mu.Lock()
				m.lastPublicCert = r.cert
				m.mu.Unlock()
				return r.cert, nil
			}
			log.Printf("[CERT] autocert GetCertificate err (sni=%q): %v", sni, r.err)
		case <-time.After(timeout):
			log.Printf("[CERT] autocert GetCertificate timeout %s (sni=%q)", timeout, sni)
		}
		if lastGood != nil {
			return lastGood, nil
		}
		// Only self-sign when we truly have nothing — browsers will show untrusted.
		// Prefer failing open with self-signed so Admin/tunnel can still run with -insecure.
		fb, fbErr := m.ensureFallbackCert()
		if fbErr == nil {
			if !emptySNI {
				log.Printf("[CERT] WARNING: serving self-signed for public SNI %q — LE not ready (open :80 for HTTP-01)", sni)
			}
			return fb, nil
		}
		return nil, fbErr
	}

	m.mu.RLock()
	cert := m.cert
	m.mu.RUnlock()

	if cert == nil {
		return nil, fmt.Errorf("no certificate available")
	}
	return cert, nil
}

func (m *Manager) refreshPublicCert(h *tls.ClientHelloInfo) {
	if m.autocertMgr == nil || h == nil {
		return
	}
	c, err := m.autocertMgr.GetCertificate(h)
	if err != nil || c == nil {
		return
	}
	m.mu.Lock()
	m.lastPublicCert = c
	m.mu.Unlock()
}

// WarmPublicCert tries to obtain LE cert at startup (best-effort, non-blocking caller).
func (m *Manager) WarmPublicCert(domain string) {
	if m.autocertMgr == nil || domain == "" {
		return
	}
	h := &tls.ClientHelloInfo{ServerName: domain}
	c, err := m.autocertMgr.GetCertificate(h)
	if err != nil {
		log.Printf("[CERT] warm %s: %v (will retry on handshake; ensure :80 open for ACME)", domain, err)
		return
	}
	if c != nil {
		m.mu.Lock()
		m.lastPublicCert = c
		m.mu.Unlock()
		log.Printf("[CERT] warm OK for %s", domain)
	}
}

// ensureFallbackCert returns a long-lived self-signed cert for emergency TLS
// (loopback Admin probes, IP access with InsecureSkipVerify).
func (m *Manager) ensureFallbackCert() (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cert != nil {
		return m.cert, nil
	}
	names := make([]string, 0, len(m.domains)+3)
	names = append(names, m.domains...)
	names = append(names, "localhost", "127.0.0.1")
	cert, err := generateSelfSigned(names)
	if err != nil {
		return nil, err
	}
	m.cert = cert
	log.Printf("[CERT] fallback self-signed ready for empty/IP SNI (domains=%v)", names)
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
		NextProtos:         []string{"h2", "http/1.1"},
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

	var dns []string
	var ips []net.IP
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if ip := net.ParseIP(d); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, d)
		}
	}
	if len(dns) == 0 && len(ips) == 0 {
		dns = []string{"localhost"}
	}
	cn := "localhost"
	if len(dns) > 0 {
		cn = dns[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"AERO Protocol"},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
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
