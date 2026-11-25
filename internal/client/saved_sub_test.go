// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSavedSubscriptionRoundTripAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AERO_DATA_DIR", dir)

	if got := LoadSavedSubscription(); got != "" {
		t.Fatalf("没保存过应为空: %q", got)
	}
	const a = "https://node.example.com/sub/AAAA"
	const b = "https://node.example.com/sub/BBBB"

	if changed, err := SaveSubscriptionURL(a); err != nil || !changed {
		t.Fatalf("首次保存: changed=%v err=%v", changed, err)
	}
	if got := LoadSavedSubscription(); got != a {
		t.Fatalf("读回 %q", got)
	}
	// 相同地址：不写盘（文件修改时间与内容都不变）
	st1, _ := os.Stat(filepath.Join(dir, savedSubFileName))
	if changed, err := SaveSubscriptionURL(a); err != nil || changed {
		t.Fatalf("相同地址不应视为改变: changed=%v err=%v", changed, err)
	}
	st2, _ := os.Stat(filepath.Join(dir, savedSubFileName))
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("相同地址不应重写文件")
	}
	// 变了：覆盖
	if changed, err := SaveSubscriptionURL("  " + b + "\n"); err != nil || !changed {
		t.Fatalf("覆盖: changed=%v err=%v", changed, err)
	}
	if got := LoadSavedSubscription(); got != b {
		t.Fatalf("覆盖后读回 %q", got)
	}
	// 目录里不留临时文件
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("残留临时文件 %s", e.Name())
		}
	}
	// 权限 0600（Windows 无此语义）
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(filepath.Join(dir, savedSubFileName)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("文件权限 %v err=%v，应为 0600", st.Mode().Perm(), err)
		}
	}
}

func TestSavedSubscriptionRejectsInvalidAndKeepsOld(t *testing.T) {
	t.Setenv("AERO_DATA_DIR", t.TempDir())
	const good = "https://node.example.com/sub/GOOD"
	if _, err := SaveSubscriptionURL(good); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		"", "   ", "http://node.example.com/sub/x", "ftp://x/y", "node.example.com/sub/x", "https://", "https:///sub/x",
		"https://node.example.com/sub/a b", "https://node.example.com/sub/a\nb", "https://node.example.com/" + strings.Repeat("a", maxSavedSubLen),
		"javascript:alert(1)",
		"https://user:pass@node.example.com/sub/x", // userinfo
		"https://user@node.example.com/sub/x",      // userinfo
		"https://node.example.com/sub/\u202Ex",     // 双向覆盖符
		"https://node.example.com/sub/a\u200Bb",    // 零宽空格
		"https://node.example.com/sub/a\u2028b",    // 行分隔符
		"https://node.example.com/sub/a\u0085b",    // NEL 控制字符
		"https://node.example.com/sub/a\u00A0b",    // 不换行空格
	}
	for _, b := range bad {
		if changed, err := SaveSubscriptionURL(b); err == nil || changed {
			t.Errorf("SaveSubscriptionURL(%q) 应被拒绝", b)
		}
	}
	if got := LoadSavedSubscription(); got != good {
		t.Fatalf("非法输入不应改动已保存的地址: %q", got)
	}
}

// 文件被改坏或被手工写成不合法的内容时，读回为空而不是返回脏数据。
func TestSavedSubscriptionIgnoresCorruptFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AERO_DATA_DIR", dir)
	for _, content := range []string{"not json", `{"url":"http://insecure/x"}`, `{"url":""}`, `{}`} {
		if err := os.WriteFile(filepath.Join(dir, savedSubFileName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := LoadSavedSubscription(); got != "" {
			t.Errorf("内容 %q 应读回空，得到 %q", content, got)
		}
	}
}
