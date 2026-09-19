package service

import (
	"context"
	"strings"
	"testing"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/secret"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

func TestVPS_StrictDomainValidation(t *testing.T) {
	box, err := secret.NewBox()
	if err != nil {
		t.Fatalf("new box: %v", err)
	}
	memStore := store.NewMemoryStore()
	svc := New(memStore, box)

	// 1. 无域名或空域名 -> 必须拒绝
	_, err = svc.Create(domain.CreateVPSParams{
		Name: "test-node", IP: "1.2.3.4", SSHPassword: "pass", Domain: "",
	})
	if err == nil || !strings.Contains(err.Error(), "域名为必填项") {
		t.Fatalf("expected error on empty domain, got %v", err)
	}

	// 2. 纯 IP 当作域名 -> 必须拒绝
	_, err = svc.Create(domain.CreateVPSParams{
		Name: "test-node", IP: "1.2.3.4", SSHPassword: "pass", Domain: "1.2.3.4",
	})
	if err == nil || !strings.Contains(err.Error(), "格式不合法") {
		t.Fatalf("expected error on raw IP domain, got %v", err)
	}

	// 3. 无效格式域名 (不包含点) -> 必须拒绝
	_, err = svc.Create(domain.CreateVPSParams{
		Name: "test-node", IP: "1.2.3.4", SSHPassword: "pass", Domain: "localhost",
	})
	if err == nil || !strings.Contains(err.Error(), "格式不合法") {
		t.Fatalf("expected error on single word domain, got %v", err)
	}
}

func TestVPS_VerifyOrSyncDomain_Localhost(t *testing.T) {
	box, _ := secret.NewBox()
	svc := New(store.NewMemoryStore(), box)

	// 127.0.0.1 不匹配随机外部域名 -> 报错
	err := svc.VerifyOrSyncDomain(context.Background(), "invalid.nonexistent.domain.xyz", "127.0.0.1")
	if err == nil {
		t.Fatalf("expected verification failure for nonexistent domain")
	}
}
