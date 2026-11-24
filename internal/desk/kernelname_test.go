// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package desk

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKernelDirForRejectsTraversalAndBadNames(t *testing.T) {
	data := t.TempDir()
	good := [][2]string{{"chrome", "133"}, {"firefox", "134.0.2"}, {"chrome", "a_b-c.1"}}
	for _, g := range good {
		key, dir, err := kernelDirFor(data, g[0], g[1])
		if err != nil {
			t.Errorf("kernelDirFor(%q,%q) 不应失败: %v", g[0], g[1], err)
			continue
		}
		if !pathWithin(filepath.Join(data, "kernels"), dir) || key != g[0]+"_"+g[1] {
			t.Errorf("kernelDirFor(%q,%q) = %q,%q", g[0], g[1], key, dir)
		}
	}
	bad := [][2]string{
		{"chrome", "/../../.."}, {"chrome", ".."}, {"chrome", "../x"}, {"chrome", `..\x`}, {"chrome", "a/b"},
		{"chrome", ""}, {"chrome", "."}, {"chrome", ".hidden"}, {"chrome", "1..2"}, {"chrome", "a b"},
		{"chrome", strings.Repeat("a", 65)}, {"chrome", "x\x00y"},
		{"", "133"}, {"safari", "17"}, {"../chrome", "1"}, {"chrome/../..", "1"},
	}
	for _, b := range bad {
		if _, _, err := kernelDirFor(data, b[0], b[1]); err == nil {
			t.Errorf("kernelDirFor(%q,%q) 应被拒绝", b[0], b[1])
		}
	}
}

func TestDeleteKernelNeverTouchesOutsideKernels(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	victim := filepath.Join(root, "victim")
	for _, d := range []string{filepath.Join(data, "kernels", "chrome_133"), victim} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(victim, "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 经典穿越：dataDir/kernels/chrome_/../../../victim
	if err := DeleteKernel(data, "chrome", "/../../../victim"); err == nil {
		t.Error("越界参数应返回错误")
	}
	if err := DeleteKernel(data, "chrome", "../../victim"); err == nil {
		t.Error("越界参数应返回错误")
	}
	if _, err := os.Stat(filepath.Join(victim, "keep.txt")); err != nil {
		t.Fatalf("kernels 之外的目录被删除了: %v", err)
	}
	if err := DeleteKernel(data, "chrome", "133"); err != nil {
		t.Fatalf("合法删除应成功: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, "kernels", "chrome_133")); !os.IsNotExist(err) {
		t.Errorf("合法内核目录应被删除: %v", err)
	}
}

func TestTriggerKernelDownloadValidatesBeforeStarting(t *testing.T) {
	data := t.TempDir()
	cases := []struct{ typ, ms, url string }{
		{"chrome", "../x", "https://storage.googleapis.com/a.zip"},
		{"chrome", "133", "http://storage.googleapis.com/a.zip"},        // 非 https
		{"chrome", "133", "https://evil.example.com/a.zip"},             // 非官方主机
		{"chrome", "133", "https://storage.googleapis.com@evil.test/a"}, // 用户信息伪装
		{"chrome", "133", "https://storage.googleapis.com.evil.test/a"}, // 后缀伪装
		{"chrome", "133", "file:///etc/passwd"},
		{"chrome", "133", "https://storage.googleapis.com/evil-bucket/a.zip"},                       // 同主机但不是官方 bucket
		{"chrome", "133", "https://storage.googleapis.com/chrome-for-testing-public/../evil/a.zip"}, // 路径穿越
		{"chrome", "133", "https://storage.googleapis.com/chrome-for-testing-publicx/a.zip"},        // 前缀不完整
		{"chrome", "133", "https://storage.googleapis.com:8443/chrome-for-testing-public/a.zip"},    // 非默认端口
		{"firefox", "134", "https://playwright.azureedge.net/builds/chromium/1/a.zip"},              // 官方主机的其他路径
		{"chrome", "133", ""},
	}
	for _, c := range cases {
		var got error
		called := false
		TriggerKernelDownload(data, c.typ, c.ms, c.url, func(err error) { called, got = true, err })
		if !called || got == nil {
			t.Errorf("TriggerKernelDownload(%q,%q,%q) 应同步失败", c.typ, c.ms, c.url)
		}
		if GetKernelProgress(c.typ+"_"+c.ms) != 0 {
			t.Errorf("校验失败不应登记下载进度: %q %q", c.typ, c.ms)
		}
	}
	if _, err := os.Stat(filepath.Join(data, "kernels")); !os.IsNotExist(err) {
		t.Errorf("校验失败不应创建 kernels 目录: %v", err)
	}
	for _, ok := range []string{
		"https://storage.googleapis.com/chrome-for-testing-public/133/win64/chrome-win64.zip",
		"https://playwright.azureedge.net/builds/firefox/1/firefox-win64.zip",
	} {
		if err := validateKernelURL(ok); err != nil {
			t.Errorf("官方地址应通过: %s: %v", ok, err)
		}
	}
}

// 官方源即使返回 30x，也只能跳到 https 的官方主机；跳到其他主机或 http 必须被拒绝。
func TestKernelDownloadClientRejectsUnofficialRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("evil")) }))
	defer target.Close()
	mk := func(rawURL string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, bad := range []string{target.URL, "http://storage.googleapis.com/chrome-for-testing-public/a.zip", "https://evil.example.com/a.zip", "https://user@storage.googleapis.com/x"} {
		if err := checkKernelRedirect(mk(bad), nil); err == nil {
			t.Errorf("重定向到 %s 应被拒绝", bad)
		}
	}
	if err := checkKernelRedirect(mk("https://storage.googleapis.com/chrome-for-testing-public/1/a.zip"), nil); err != nil {
		t.Errorf("官方主机应放行: %v", err)
	}
	if err := checkKernelRedirect(mk("https://storage.googleapis.com/x"), make([]*http.Request, 5)); err == nil {
		t.Error("重定向次数过多应被拒绝")
	}
	// 经真实客户端：官方主机以外的重定向目标被拒绝，请求不会到达目标。
	hit := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL, http.StatusFound) }))
	defer redir.Close()
	c := createKernelHTTPClient(false)
	if resp, err := c.Get(redir.URL); err == nil {
		_ = resp.Body.Close()
		t.Error("跳到非官方主机的重定向应返回错误")
	}
	if hit {
		t.Error("重定向目标不应被请求")
	}
}
