package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/secret"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

func parsePurityOutput(rawOutput string) (purityScore int, aiBlocked bool, googleClean bool, cfClean bool, isWarp bool) {
	parts := strings.Split(rawOutput, ",")
	gCode, cfCode, aiCode, warpOn := "000", "000", "000", "0"
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "G":
				gCode = kv[1]
			case "CF":
				cfCode = kv[1]
			case "AI":
				aiCode = kv[1]
			case "WARP":
				warpOn = kv[1]
			}
		}
	}

	// 1. 硬门禁判定：遭遇 403 Forbidden / 429 阻断直接一票否决
	if aiCode == "403" || aiCode == "429" || aiCode == "000" {
		aiBlocked = true
	}

	// 2. 软评分计算：Google (60 分) + Cloudflare (40 分)
	if gCode == "200" {
		googleClean = true
		purityScore += 60
	}
	if cfCode == "200" {
		cfClean = true
		purityScore += 40
	}
	isWarp = (warpOn == "1")
	return
}

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
			score, aiBlocked, gClean, cfClean, isWarp := parsePurityOutput(tt.rawOutput)
			if score != tt.wantPurityScore {
				t.Errorf("PurityScore = %d, want %d", score, tt.wantPurityScore)
			}
			if aiBlocked != tt.wantAIBlocked {
				t.Errorf("AIBlocked = %v, want %v", aiBlocked, tt.wantAIBlocked)
			}
			if gClean != tt.wantGoogleClean {
				t.Errorf("GoogleClean = %v, want %v", gClean, tt.wantGoogleClean)
			}
			if cfClean != tt.wantCFClean {
				t.Errorf("CFClean = %v, want %v", cfClean, tt.wantCFClean)
			}
			if isWarp != tt.wantIsWarp {
				t.Errorf("IsWARP = %v, want %v", isWarp, tt.wantIsWarp)
			}
			isTier1Safe := (!aiBlocked && score >= 90)
			if isTier1Safe != tt.wantTier1Safe {
				t.Errorf("Tier1Safe eligibility = %v, want %v", isTier1Safe, tt.wantTier1Safe)
			}
		})
	}
}

func TestStoreUpdatePurity(t *testing.T) {
	mem := store.NewMemoryStore()
	h := &domain.VPSHost{
		IP:      "1.2.3.4",
		SSHPort: 22,
		Domain:  "clean.example.com",
		Status:  "online",
	}
	id, err := mem.Create(h, "enc_pass")
	if err != nil {
		t.Fatalf("Create host failed: %v", err)
	}

	// 更新纯净度
	if err := mem.UpdatePurity(id, 100, false, true, true, false); err != nil {
		t.Fatalf("UpdatePurity failed: %v", err)
	}

	got, _, err := mem.Get(id)
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
	mem := store.NewMemoryStore()
	box, _ := secret.NewBox()
	svc := New(mem, box)

	ctx, cancel := context.WithCancel(context.Background())
	svc.StartPurityTicker(ctx, 10*time.Millisecond)

	// 等待短暂触发后优雅取消
	time.Sleep(25 * time.Millisecond)
	cancel()
}
