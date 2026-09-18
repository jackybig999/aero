package snimatrix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatrixMatchingAndFallback(t *testing.T) {
	mgr := New("")

	// 1. 电信 + 日本 -> edge.microsoft.com
	sni1 := mgr.Match("china_telecom", "JP")
	if sni1 != "edge.microsoft.com" {
		t.Errorf("expected edge.microsoft.com for telecom/JP, got %s", sni1)
	}

	// 2. 联通 + 日本 -> gateway.icloud.com
	sni2 := mgr.Match("china_unicom", "JP")
	if sni2 != "gateway.icloud.com" {
		t.Errorf("expected gateway.icloud.com for unicom/JP, got %s", sni2)
	}

	// 3. 移动 + 香港 -> live.azure.com
	sni3 := mgr.Match("china_mobile", "HK")
	if sni3 != "live.azure.com" {
		t.Errorf("expected live.azure.com for mobile/HK, got %s", sni3)
	}

	// 4. 中文别名解析: "中国电信" + "东京" -> edge.microsoft.com
	sni4 := mgr.Match("中国电信", "东京-01")
	if sni4 != "edge.microsoft.com" {
		t.Errorf("expected edge.microsoft.com for alias, got %s", sni4)
	}

	// 5. 未知运营商 + 未知地区 -> 优雅兜底
	sni5 := mgr.Match("unknown_corp", "MARS")
	if sni5 == "" {
		t.Errorf("expected non-empty fallback SNI for unknown input, got empty")
	}

	// 6. 验证持久化与保存加载
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "sni_matrix.json")
	if err := mgr.SaveFile(testPath); err != nil {
		t.Fatalf("failed to save matrix: %v", err)
	}
	if _, err := os.Stat(testPath); err != nil {
		t.Fatalf("saved file not found: %v", err)
	}

	mgr2 := New(testPath)
	if sniLoaded := mgr2.Match("china_telecom", "JP"); sniLoaded != "edge.microsoft.com" {
		t.Errorf("reloaded match mismatch: %s", sniLoaded)
	}
}
