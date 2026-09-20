package service

import (
	"testing"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/secret"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

func TestVPS_UpdateMeta(t *testing.T) {
	box, err := secret.NewBox()
	if err != nil {
		t.Fatalf("new box: %v", err)
	}
	memStore := store.NewMemoryStore()
	svc := New(memStore, box)

	// 创建初始主机
	p := domain.CreateVPSParams{
		Name: "node-orig", Role: "node", IP: "11.22.33.44",
		SSHPort: 22, SSHUsername: "root", SSHPassword: "pass",
		Domain: "de5.example.com", Remark: "initial remark",
	}
	// bypass verify via direct store create for pure unit test
	cipher, _ := box.Encrypt("pass")
	id, err := memStore.Create(&domain.VPSHost{
		Name: p.Name, Role: p.Role, IP: p.IP, SSHPort: p.SSHPort,
		SSHUsername: p.SSHUsername, Domain: p.Domain, Remark: p.Remark,
	}, cipher)
	if err != nil {
		t.Fatalf("create host: %v", err)
	}

	// 执行 UpdateMeta
	err = svc.UpdateMeta(id, domain.UpdateVPSParams{
		Name: "node-renamed",
		Role: "edge",
		SSHPort: 2222,
		SSHUsername: "admin",
		Remark: "updated remark",
	})
	if err != nil {
		t.Fatalf("UpdateMeta: %v", err)
	}

	// 重新获取并校验
	h, err := svc.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if h.Name != "node-renamed" || h.Role != "edge" || h.SSHPort != 2222 || h.SSHUsername != "admin" || h.Remark != "updated remark" {
		t.Fatalf("UpdateMeta did not persist properly: %+v", h)
	}
}

func TestVPS_CalculateCapacity(t *testing.T) {
	// 1. 低配小鸡 (1C512M) 轻载
	m1 := &domain.HostMetrics{
		ProbeOK: true, MemTotalMB: 512, MemPercent: 45, CPUPercent: 20, LatencyMS: 60,
	}
	score1, tier1, state1 := CalculateCapacity(m1)
	if tier1 != 1 {
		t.Errorf("expected tier 1 for 512MB VPS, got %d", tier1)
	}
	if score1 < 80 || state1 != "excellent" {
		t.Errorf("expected high score and excellent state, got score=%d, state=%s", score1, state1)
	}

	// 2. 低配小鸡 内存过载 (95% 内存，80% CPU)
	m2 := &domain.HostMetrics{
		ProbeOK: true, MemTotalMB: 1024, MemPercent: 95, CPUPercent: 85, LatencyMS: 300,
	}
	score2, tier2, state2 := CalculateCapacity(m2)
	if tier2 != 1 {
		t.Errorf("expected tier 1 for 1024MB VPS, got %d", tier2)
	}
	if score2 >= 50 || state2 == "excellent" {
		t.Errorf("expected overload penalty for high load, got score=%d state=%s", score2, state2)
	}

	// 3. 企业级万兆骨干机 (8C16G)
	m3 := &domain.HostMetrics{
		ProbeOK: true, MemTotalMB: 16384, MemPercent: 30, CPUPercent: 15, LatencyMS: 40,
	}
	score3, tier3, state3 := CalculateCapacity(m3)
	if tier3 != 3 {
		t.Errorf("expected tier 3 for 16GB VPS, got %d", tier3)
	}
	if score3 < 90 || state3 != "excellent" {
		t.Errorf("expected top score for low load enterprise host, got score=%d state=%s", score3, state3)
	}

	// 4. 探针异常/离线主机
	m4 := &domain.HostMetrics{ProbeOK: false}
	score4, _, state4 := CalculateCapacity(m4)
	if score4 != 0 || state4 != "offline" {
		t.Errorf("expected score=0, state=offline for failed probe, got score=%d state=%s", score4, state4)
	}
}
