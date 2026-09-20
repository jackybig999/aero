// Copyright 2026 AERO Protocol Contributors
// Plan.md Phase 2.5: 平铺测试 — 真实打靶纯净度打分与硬门禁一票否决回测
package main

import (
	"context"
	"testing"
	"time"
)

func TestPurityEvaluationLogic(t *testing.T) {
	tests := []struct {
		name            string
		rawOutput       string
		wantPurityScore int
		wantAIBlocked   bool
		wantGoogleClean bool
		wantCFClean     bool
		wantIsWarp      bool
		wantTier1Safe   bool
	}{
		{
			name:            "双原生纯净 IP (通过全部打靶，无封控)",
			rawOutput:       "G:200,CF:200,AI:404,WARP:0",
			wantPurityScore: 100,
			wantAIBlocked:   false,
			wantGoogleClean: true,
			wantCFClean:     true,
			wantIsWarp:      false,
			wantTier1Safe:   true, // 准入 Tier 1 (AI_SAFE)
		},
		{
			name:            "AI 平台封锁一票否决 (遭遇 403 Forbidden)",
			rawOutput:       "G:200,CF:200,AI:403,WARP:0",
			wantPurityScore: 100,
			wantAIBlocked:   true, // 硬门禁拦截
			wantGoogleClean: true,
			wantCFClean:     true,
			wantIsWarp:      false,
			wantTier1Safe:   false, // 坚决剥夺 Tier 1 资格
		},
		{
			name:            "Google 遭遇 429 验证码 (仅 CF 正常)",
			rawOutput:       "G:429,CF:200,AI:404,WARP:0",
			wantPurityScore: 40,
			wantAIBlocked:   false,
			wantGoogleClean: false,
			wantCFClean:     true,
			wantIsWarp:      false,
			wantTier1Safe:   false, // 分数不足 90，不得进入 Tier 1
		},
		{
			name:            "外挂 WARP 洗白 Web，但 AI 仍识别拦截",
			rawOutput:       "G:200,CF:200,AI:403,WARP:1",
			wantPurityScore: 100,
			wantAIBlocked:   true, // 破除 WARP 盲信：AI 拦截一票否决
			wantGoogleClean: true,
			wantCFClean:     true,
			wantIsWarp:      true,
			wantTier1Safe:   false, // 严禁冒充 Tier 1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := EvaluatePurity(tt.rawOutput, 1)
			if res.PurityScore != tt.wantPurityScore {
				t.Errorf("PurityScore = %d, want %d", res.PurityScore, tt.wantPurityScore)
			}
			if res.AIBlocked != tt.wantAIBlocked {
				t.Errorf("AIBlocked = %v, want %v", res.AIBlocked, tt.wantAIBlocked)
			}
			if res.GoogleClean != tt.wantGoogleClean {
				t.Errorf("GoogleClean = %v, want %v", res.GoogleClean, tt.wantGoogleClean)
			}
			if res.CFClean != tt.wantCFClean {
				t.Errorf("CFClean = %v, want %v", res.CFClean, tt.wantCFClean)
			}
			if res.IsWARPEgress != tt.wantIsWarp {
				t.Errorf("IsWARP = %v, want %v", res.IsWARPEgress, tt.wantIsWarp)
			}
			isTier1Safe := (!res.AIBlocked && res.PurityScore >= 90)
			if isTier1Safe != tt.wantTier1Safe {
				t.Errorf("Tier1Safe eligibility = %v, want %v", isTier1Safe, tt.wantTier1Safe)
			}
		})
	}
}

func TestStoreUpdatePurity(t *testing.T) {
	mem := NewMemoryVPSStore()
	p := CreateVPSParams{
		IP:          "1.2.3.4",
		SSHPort:     22,
		Domain:      "clean.example.com",
		SSHPassword: "pass",
	}
	host, err := mem.Create(p)
	if err != nil {
		t.Fatalf("Create host failed: %v", err)
	}
	id := host.ID

	// 更新纯净度
	res := &PurityResult{
		VPSID:        id,
		PurityScore:  100,
		AIBlocked:    false,
		GoogleClean:  true,
		CFClean:      true,
		IsWARPEgress: false,
		ProbeAt:      time.Now(),
	}
	if err := mem.UpdatePurity(id, res); err != nil {
		t.Fatalf("UpdatePurity failed: %v", err)
	}

	got, err := mem.Get(id)
	if err != nil {
		t.Fatalf("Get host failed: %v", err)
	}
	if got.PurityScore != 100 || got.AIBlocked || !got.GoogleClean || !got.CFClean || got.IsWARPEgress {
		t.Errorf("unexpected host purity fields: %+v", got)
	}
	if got.LastPurityProbeAt == nil {
		t.Errorf("expected LastPurityProbeAt to be populated")
	}
}

func TestPurityTickerLifecycle(t *testing.T) {
	mem := NewMemoryVPSStore()
	box, _ := NewSecretBox()
	svc := NewVPSService(mem, box, nil)

	ctx, cancel := context.WithCancel(context.Background())
	svc.StartPurityTicker(ctx, 10*time.Millisecond)

	time.Sleep(25 * time.Millisecond)
	cancel()
}
