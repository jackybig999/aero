// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package listener

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
	"github.com/aero-protocol/aero-edge/internal/config"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

// Manager 管理多个端口监听器
type Manager struct {
	handler   http.Handler
	validator *auth.Validator
	tlsConfig *tls.Config
	servers   []*http.Server
	listeners []net.Listener
	quicLns   []*quic.Listener
	wg        sync.WaitGroup
}

// NewManager 创建监听器管理器
func NewManager(handler http.Handler, validator *auth.Validator, cfg *config.ServerConfig, echKeys []tls.EncryptedClientHelloKey) (*Manager, error) {
	m := &Manager{
		handler:   handler,
		validator: validator,
	}

	// 构建 TLS 配置
	// h2 preferred; http/1.1 kept so Admin/sub probes and simple clients work.
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}

	if cfg.TLSCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cfg.TLSCert}
	}

	// 启用真 ECH（Go 1.24+）
	if len(echKeys) > 0 {
		tlsCfg.EncryptedClientHelloKeys = echKeys
		log.Printf("[ECH] Server ECH enabled with %d key(s)", len(echKeys))
	}

	m.tlsConfig = tlsCfg
	return m, nil
}

// Start 启动所有端口监听
func (m *Manager) Start(cfg *config.ServerConfig) error {
	// 如果有动态证书回调，注入到 TLS 配置
	if cfg.GetCertificate != nil {
		m.tlsConfig.GetCertificate = cfg.GetCertificate
	}

	// TLS 端口
	for _, port := range cfg.TLSPorts {
		addr := fmt.Sprintf(":%d", port)
		ln, err := tls.Listen("tcp", addr, m.tlsConfig)
		if err != nil {
			return fmt.Errorf("tls listen %s: %w", addr, err)
		}
		m.listeners = append(m.listeners, ln)

		server := &http.Server{
			Addr:              addr,
			Handler:           m.handler,
			TLSConfig:         m.tlsConfig,
			ReadTimeout:       0, // 长连接隧道不允许读超时
			WriteTimeout:      0,
			IdleTimeout:       0,
			ReadHeaderTimeout: 10 * time.Second, // 仅限制握手头，防慢连
			MaxHeaderBytes:    16 << 10,
		}
		// 单 TCP 连接上合理并发流；客户端应用 h2 复用，服务端不无限放大
		if err := http2.ConfigureServer(server, &http2.Server{
			MaxConcurrentStreams: 256,
			IdleTimeout:          0,
		}); err != nil {
			return fmt.Errorf("configure http2 %s: %w", addr, err)
		}
		m.servers = append(m.servers, server)

		m.wg.Add(1)
		go func(s *http.Server, l net.Listener, p int) {
			defer m.wg.Done()
			log.Printf("[LISTEN] TLS %d (HTTP/2)", p)
			if err := s.Serve(l); err != nil {
				log.Printf("[LISTEN] TLS %d stopped: %v", p, err)
			}
		}(server, ln, port)
	}

	// Plain HTTP 端口（80）
	for _, port := range cfg.PlainPorts {
		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("plain listen %s: %w", addr, err)
		}
		m.listeners = append(m.listeners, ln)

		server := &http.Server{
			Addr:         addr,
			Handler:      m.handler,
			ReadTimeout:  0,
			WriteTimeout: 0,
			IdleTimeout:  0,
		}
		m.servers = append(m.servers, server)

		m.wg.Add(1)
		go func(s *http.Server, l net.Listener, p int) {
			defer m.wg.Done()
			log.Printf("[LISTEN] Plain HTTP %d (CONNECT fallback)", p)
			if err := s.Serve(l); err != nil {
				log.Printf("[LISTEN] Plain HTTP %d stopped: %v", p, err)
			}
		}(server, ln, port)
	}

	// QUIC 端口
	for _, port := range cfg.QUICPorts {
		addr := fmt.Sprintf(":%d", port)
		ln, err := StartQUIC(addr, m.tlsConfig, NewQUICHandler(m.validator))
		if err != nil {
			return fmt.Errorf("quic listen %s: %w", addr, err)
		}
		m.quicLns = append(m.quicLns, ln)
		log.Printf("[LISTEN] QUIC %d", port)
	}

	return nil
}

// Wait 阻塞等待所有监听器退出
func (m *Manager) Wait() {
	m.wg.Wait()
}

// Close 关闭所有监听器（优雅：先 Shutdown 再关 listener）
func (m *Manager) Close() {
	// 先停接新连接，给进行中的 CONNECT 一点收尾时间
	for _, s := range m.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = s.Shutdown(ctx)
		cancel()
	}
	for _, ln := range m.listeners {
		_ = ln.Close()
	}
	for _, ln := range m.quicLns {
		_ = ln.Close()
	}
}
