package fingerprint

import (
	"strings"
	"testing"
)

func TestFingerprintEngine(t *testing.T) {
	// 1. 同一 Seed 确定性检验
	cfg1 := GenerateFingerprintConfig("test_seed_123", "JP", "chrome", "133.0.6943.98")
	cfg2 := GenerateFingerprintConfig("test_seed_123", "JP", "chrome", "133.0.6943.98")

	if cfg1.ScreenWidth != cfg2.ScreenWidth || cfg1.HardwareConcurrency != cfg2.HardwareConcurrency || cfg1.CanvasNoise != cfg2.CanvasNoise {
		t.Fatalf("相同 Seed 生成指纹不一致: cfg1=%+v, cfg2=%+v", cfg1, cfg2)
	}

	// 2. 不同 Seed 独立性隔离检验
	cfg3 := GenerateFingerprintConfig("another_seed_456", "US", "chrome", "133.0.6943.98")
	if cfg1.CanvasNoise == cfg3.CanvasNoise && cfg1.AudioNoise == cfg3.AudioNoise {
		t.Errorf("不同 Seed 产生了相同的噪声参数")
	}

	// 3. 国家代码时区与语言自动联动检验
	if cfg1.Timezone != "Asia/Tokyo" || cfg1.Languages[0] != "ja-JP" {
		t.Errorf("日本地域联动异常: Timezone=%s, Lang=%v", cfg1.Timezone, cfg1.Languages)
	}

	if cfg3.Timezone != "America/New_York" || cfg3.Languages[0] != "en-US" {
		t.Errorf("美国地域联动异常: Timezone=%s, Lang=%v", cfg3.Timezone, cfg3.Languages)
	}

	// 4. UA 版本精准对齐检验
	if !strings.Contains(cfg1.UserAgent, "Chrome/133") {
		t.Errorf("Chrome UA 未包含内核大版本号: %s", cfg1.UserAgent)
	}

	ffCfg := GenerateFingerprintConfig("ff_seed", "DE", "firefox", "134.0.2")
	if !strings.Contains(ffCfg.UserAgent, "Firefox/134.0.2") {
		t.Errorf("Firefox UA 未对齐: %s", ffCfg.UserAgent)
	}

	// 5. JavaScript 防御脚本注入代码生成验证
	script := BuildFingerprintScript(cfg1)
	if !strings.Contains(script, "webdriver") || !strings.Contains(script, "UNMASKED_VENDOR_WEBGL") || !strings.Contains(script, "HTMLCanvasElement.prototype.toDataURL") {
		t.Errorf("注入脚本缺少关键防御逻辑: %s", script)
	}
}
