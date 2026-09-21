package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnifiedConfigAndVPN(t *testing.T) {
	tempDir := t.TempDir()
	testConfigPath := filepath.Join(tempDir, "test_config.json")
	defer os.Remove(testConfigPath)

	cfg, err := LoadOrCreateUnifiedConfig(testConfigPath)
	if err != nil {
		t.Fatalf("加载配置文件失败: %v", err)
	}
	if cfg.AppVersion != "2.0" || cfg.Settings.DefaultKernel != "chrome" {
		t.Errorf("默认配置字段异常: %+v", cfg)
	}

	vpn, err := DetectSystemVPN()
	if err != nil {
		t.Fatalf("检测 VPN 失败: %v", err)
	}

	if vpn.Detected {
		cfg.VPN = *vpn
		if err := SaveUnifiedConfig(cfg); err != nil {
			t.Fatalf("保存 VPN 配置失败: %v", err)
		}
	}

	reloaded, err := LoadOrCreateUnifiedConfig(testConfigPath)
	if err != nil {
		t.Fatalf("重新读取配置失败: %v", err)
	}
	if vpn.Detected && !reloaded.VPN.Detected {
		t.Errorf("重新读取的配置未保留 VPN 状态: %+v", reloaded.VPN)
	}

	loc := GetHostSystemLocale()
	if loc == "" {
		t.Error("获取系统语言返回空")
	}
	t.Logf("宿主系统检测语言: %s", loc)
}

func TestLocalizedStartupURL(t *testing.T) {
	cases := map[string]string{
		"zh-CN": "https://whoer.net/zh",
		"zh-TW": "https://whoer.net/zh",
		"ja":    "https://whoer.net/ja",
		"ja-JP": "https://whoer.net/ja",
		"ru":    "https://whoer.net/ru",
		"es":    "https://whoer.net/es",
		"fr":    "https://whoer.net/fr",
		"de":    "https://whoer.net/",
		"en-US": "https://whoer.net/en",
		"en-GB": "https://whoer.net/en",
	}

	for lang, expected := range cases {
		got := GetDefaultFingerprintCheckURL(lang)
		if got != expected {
			t.Errorf("GetDefaultFingerprintCheckURL(%q) = %q, want %q", lang, got, expected)
		}
	}
}

func TestFileLineCountGovernance(t *testing.T) {
	err := filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := 0
		for _, b := range data {
			if b == '\n' {
				lines++
			}
		}
		if len(data) > 0 && data[len(data)-1] != '\n' {
			lines++
		}
		if lines > 300 {
			t.Errorf("文件行数超出 300 行红线: %s (%d 行)", path, lines)
		} else {
			t.Logf("合规: %s (%d 行)", path, lines)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历目录失败: %v", err)
	}
}
