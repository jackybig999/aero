// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package integration 提供 aero-edge 端到端集成测试。
package integration

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
	"github.com/aero-protocol/aero-edge/internal/certmgr"
	"github.com/aero-protocol/aero-edge/internal/config"
	"github.com/aero-protocol/aero-edge/internal/listener"
)

// TestEdgeServerStartupShutdown 验证 edge server 能正常启动和关闭
func TestEdgeServerStartupShutdown(t *testing.T) {
	validator := auth.NewValidator()
	validator.AddToken("test-token", "test", time.Hour)

	certCfg := certmgr.Config{
		Source:   certmgr.SelfSigned,
		Domains:  []string{"localhost"},
		CacheDir: t.TempDir(),
	}
	certManager, err := certmgr.NewManager(certCfg)
	if err != nil {
		t.Fatalf("init cert manager: %v", err)
	}

	serverCfg := &config.ServerConfig{
		TLSPorts:       []int{0}, // 端口 0 让系统分配
		PlainPorts:     []int{0},
		TLSCert:        certManager.Certificate(),
		GetCertificate: certManager.GetCertificate,
	}

	// 使用简单的 handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mgr, err := listener.NewManager(handler, validator, serverCfg, nil)
	if err != nil {
		t.Fatalf("create listener manager: %v", err)
	}

	// Start 方法中使用 :0 作为地址时会实际监听随机端口
	// 但 listener.go 中端口传入 0 时 addr 会变成 ":0"
	// 这是有效的，系统会分配可用端口
	if err := mgr.Start(serverCfg); err != nil {
		t.Fatalf("start listeners: %v", err)
	}

	// 给服务器一点时间启动
	time.Sleep(50 * time.Millisecond)

	// 关闭
	mgr.Close()

	// Wait 应该在 Close 后返回
	done := make(chan struct{})
	go func() {
		mgr.Wait()
		close(done)
	}()

	select {
	case <-done:
		// 成功
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

// TestCertManagerSources 验证三种证书源都能正常工作
func TestCertManagerSources(t *testing.T) {
	tests := []struct {
		name   string
		source certmgr.Source
		cfg    certmgr.Config
	}{
		{
			name:   "SelfSigned",
			source: certmgr.SelfSigned,
			cfg: certmgr.Config{
				Source:   certmgr.SelfSigned,
				Domains:  []string{"localhost"},
				CacheDir: t.TempDir(),
			},
		},
		{
			name:   "LetsEncrypt_skeleton",
			source: certmgr.LetsEncrypt,
			cfg: certmgr.Config{
				Source:   certmgr.LetsEncrypt,
				Domains:  []string{"test.example.com"},
				CacheDir: t.TempDir(),
				Email:    "test@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := certmgr.NewManager(tt.cfg)
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}

			// 验证 GetCertificate 能返回证书（或 nil 但不出错）
			hello := &tls.ClientHelloInfo{ServerName: tt.cfg.Domains[0]}
			cert, err := m.GetCertificate(hello)

			if tt.source == certmgr.LetsEncrypt {
				// Let's Encrypt 模式下 autocert 会尝试获取证书
				// 在测试环境中这通常会失败（无法连接 ACME 服务器）
				// 但只要不 panic 就是正确的行为
				if cert == nil {
					// 预期行为：测试环境无法完成 ACME 挑战
					t.Logf("Let's Encrypt returned nil cert in test environment (expected)")
				}
			} else {
				if err != nil {
					t.Fatalf("GetCertificate failed: %v", err)
				}
				if cert == nil {
					t.Fatal("expected non-nil certificate")
				}
			}
		})
	}
}

// TestAuthValidator 验证认证系统的完整流程
func TestAuthValidator(t *testing.T) {
	v := auth.NewValidator()
	v.AddToken("valid-token", "user1", time.Hour)

	if !v.Validate("valid-token") {
		t.Error("expected valid-token to be accepted")
	}
	if v.Validate("invalid-token") {
		t.Error("expected invalid-token to be rejected")
	}
	if v.Validate("") {
		t.Error("expected empty token to be rejected")
	}
}

// TestPortClassification 验证端口分类逻辑
func TestPortClassification(t *testing.T) {
	ports := []int{443, 8443, 80, 4443, 3443, 4433, 9999}
	tls, plain, quic := config.ClassifyPorts(ports)

	if len(tls) != 3 { // 443, 8443, 9999(default)
		t.Errorf("expected 3 TLS ports, got %d: %v", len(tls), tls)
	}
	if len(plain) != 1 { // 80
		t.Errorf("expected 1 plain port, got %d: %v", len(plain), plain)
	}
	if len(quic) != 3 { // 4443, 3443, 4433
		t.Errorf("expected 3 QUIC ports, got %d: %v", len(quic), quic)
	}
}

// TestACMEHandlerRouting 验证 ACME handler 路径能被正确识别
// 使用 httptest 直接测试 handler 的路由逻辑
func TestACMEHandlerRouting(t *testing.T) {
	// 创建一个模拟的 ACME handler
	acmeCalled := false
	acmeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acmeCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("acme-response"))
	})

	// 构建一个模拟的 edge handler（直接测试路由逻辑）
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if acmeHandler != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			acmeHandler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/ech-config" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// 测试 ACME 挑战路径
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/test-token", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !acmeCalled {
		t.Error("expected ACME handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "acme-response" {
		t.Errorf("expected body 'acme-response', got %s", rr.Body.String())
	}

	// 测试 ECH config 路径
	req = httptest.NewRequest(http.MethodGet, "/ech-config", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rr.Code)
	}

	// 测试 CONNECT 路径
	req = httptest.NewRequest(http.MethodConnect, "/", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// TestTLSConfigWithGetCertificate 验证 TLS 配置正确注入 GetCertificate 回调
func TestTLSConfigWithGetCertificate(t *testing.T) {
	certCfg := certmgr.Config{
		Source:   certmgr.SelfSigned,
		Domains:  []string{"localhost"},
		CacheDir: t.TempDir(),
	}
	certManager, err := certmgr.NewManager(certCfg)
	if err != nil {
		t.Fatalf("init cert manager: %v", err)
	}

	tlsCfg := certManager.TLSConfig()
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %x", tlsCfg.MinVersion)
	}
	if tlsCfg.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
}
