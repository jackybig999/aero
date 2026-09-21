package kernel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/domain/proxy"
)

func TestKernelAndBrowsers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	kernels, err := FetchRecentKernels(ctx, nil)
	if err != nil {
		t.Fatalf("获取内核版本失败: %v", err)
	}
	if len(kernels) == 0 {
		t.Fatal("未检索到任何内核版本信息")
	}

	for _, k := range kernels {
		t.Logf("内核: %-8s | Milestone: %-4s | 版本: %-16s | 直链: %s", k.Type, k.Milestone, k.Version, k.DownloadURL)
	}

	localBrowsers := DetectLocalBrowsers()
	for _, b := range localBrowsers {
		t.Logf("检测到本机浏览器: 类型=%s, 路径=%s", b.Type, b.Path)
	}

	p1, err := FindFreePort(9222)
	if err != nil {
		t.Fatalf("查找端口失败: %v", err)
	}
	t.Logf("分配端口: %d", p1)

	proxyCfg := &proxy.ProxyConfig{
		Enabled:  true,
		Protocol: "socks5",
		Host:     "127.0.0.1",
		Port:     7890,
	}
	prefs := GenerateFirefoxPrefs(proxyCfg, &fingerprint.FingerprintConfig{Languages: []string{"zh-CN", "zh"}}, 2828)
	if !strings.Contains(prefs, "127.0.0.1") || !strings.Contains(prefs, "media.peerconnection.enabled\", false") {
		t.Errorf("prefs.js 生成异常: %s", prefs)
	}

	extDir := t.TempDir()
	xpi, err := BuildFirefoxFingerprintExtension(extDir, "console.log('fingerprint defense active');")
	if err != nil {
		t.Fatalf("生成扩展失败: %v", err)
	}
	t.Logf("Firefox 动态指纹防御扩展 (.xpi) 生成成功: %s", xpi)
}

func TestValidateAndCleanKernelDir(t *testing.T) {
	testDir := t.TempDir() + "/corrupt"
	_ = os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)

	status, _, _ := ValidateKernelDir("non_existing_dir", "firefox")
	if status != "not_downloaded" {
		t.Errorf("不存在的目录状态应为 not_downloaded, 实际为 %s", status)
	}

	_ = os.MkdirAll(testDir, 0755)
	_ = os.WriteFile(testDir+"/firefox.exe", []byte("fake"), 0755)
	status, _, sizeMB := ValidateKernelDir(testDir, "firefox")
	if status != "corrupted" {
		t.Errorf("残缺内核目录状态应为 corrupted, 实际为 %s (size: %.4f MB)", status, sizeMB)
	}

	err := CleanKernelDir(testDir)
	if err != nil {
		t.Fatalf("清理残缺目录失败: %v", err)
	}
	if _, err := os.Stat(testDir); !os.IsNotExist(err) {
		t.Errorf("CleanKernelDir 未能彻底删除目录")
	}
}

func TestSessionAndCookiePersistence(t *testing.T) {
	tempUserData := t.TempDir()
	fp := &fingerprint.FingerprintConfig{Languages: []string{"zh-CN", "zh"}}
	configureChromeUserDataLocale(tempUserData, fp)

	prefData, err := os.ReadFile(filepath.Join(tempUserData, "Default", "Preferences"))
	if err != nil {
		t.Fatalf("读取 Chrome Preferences 失败: %v", err)
	}
	prefStr := string(prefData)
	if !strings.Contains(prefStr, `"restore_on_startup": 1`) {
		t.Errorf("Chrome 未配置会话自动恢复 (restore_on_startup: 1)")
	}
	if !strings.Contains(prefStr, `"cookies": 1`) {
		t.Errorf("Chrome 未配置 Cookie 持久化 (cookies: 1)")
	}

	ffPrefs := GenerateFirefoxPrefs(nil, fp, 2828)
	if !strings.Contains(ffPrefs, `user_pref("browser.startup.page", 3);`) {
		t.Errorf("Firefox 未配置标签页会话恢复 (browser.startup.page: 3)")
	}
	if !strings.Contains(ffPrefs, `user_pref("privacy.clearOnShutdown.cookies", false);`) {
		t.Errorf("Firefox 未配置退出防清理 Cookie")
	}
}

func TestSafariKernelAndEmulation(t *testing.T) {
	fp := fingerprint.GenerateFingerprintConfig("", "US", "safari", "17.5")
	if fp.Platform != "MacIntel" {
		t.Errorf("Safari 平台指纹应为 MacIntel, 实际为: %s", fp.Platform)
	}
	if !strings.Contains(fp.UserAgent, "Safari") || strings.Contains(fp.UserAgent, "Chrome") {
		t.Errorf("Safari UA 应为纯正 Safari, 实际为: %s", fp.UserAgent)
	}
	if fp.WebGLVendor != "Google Inc. (Apple)" {
		t.Errorf("Safari WebGLVendor 应为 Apple, 实际为: %s", fp.WebGLVendor)
	}

	script := fingerprint.BuildFingerprintScript(fp)
	if !strings.Contains(script, "MacIntel") {
		t.Errorf("指纹注入脚本未包含 MacIntel 平台")
	}
	if !strings.Contains(script, "delete window.chrome") {
		t.Errorf("指纹注入脚本未包含删除 window.chrome 防伪装识别机制")
	}

	tempDataDir := t.TempDir()
	kernels := GetAvailableKernelsWithStatus(context.Background(), tempDataDir)
	hasSafari := false
	for _, k := range kernels {
		if k.Type == "safari" {
			hasSafari = true
			if !k.IsInstalled || k.Status != "ready" {
				t.Errorf("Safari 状态应为 ready / is_installed, 实际为: %+v", k)
			}
			t.Logf("✅ 检测到 Safari 内核就绪: 版本=%s, Milestone=%s, 状态=%s", k.Version, k.Milestone, k.Status)
		}
	}
	if !hasSafari {
		t.Errorf("GetAvailableKernelsWithStatus 未能检测到 Safari 内核")
	}

	activeSafariMu.Lock()
	activeSafari[8888] = &SafariInstance{
		ProfileID: 8888,
		PID:       os.Getpid(),
		Mode:      "emulation",
	}
	activeSafariMu.Unlock()

	if !IsProfileRunning(8888) {
		t.Errorf("IsProfileRunning 应能识别活跃的 Safari 实例")
	}
	_ = StopProfileInstance(8888)
	if IsProfileRunning(8888) {
		t.Errorf("StopProfileInstance 应能清理活跃的 Safari 实例")
	}
}

func TestFirefoxAntiInvasivePolicies(t *testing.T) {
	fp := &fingerprint.FingerprintConfig{Languages: []string{"zh-CN"}}
	prefs := GenerateFirefoxPrefs(nil, fp, 2828)

	// 1. 验证首选项中严禁系统计划任务与代理注册
	antiPreferences := []string{
		`user_pref("default-browser-agent.enabled", false);`,
		`user_pref("app.update.background.scheduling.enabled", false);`,
		`user_pref("app.update.service.enabled", false);`,
		`user_pref("browser.shell.checkDefaultBrowser", false);`,
		`user_pref("browser.startup.homepage_override.mstone", "ignore");`,
		`user_pref("browser.newtabpage.activity-stream.telemetry", false);`,
		`user_pref("toolkit.telemetry.bhrPing.enabled", false);`,
		`user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);`,
	}
	for _, pref := range antiPreferences {
		if !strings.Contains(prefs, pref) {
			t.Errorf("GenerateFirefoxPrefs 缺失反系统侵入首选项: %s", pref)
		}
	}

	// 2. 验证内核企业级 policies.json 注入
	testKernelDir := t.TempDir()
	if err := EnsureFirefoxPolicies(testKernelDir); err != nil {
		t.Fatalf("EnsureFirefoxPolicies 执行失败: %v", err)
	}
	policyFile := filepath.Join(testKernelDir, "distribution", "policies.json")
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("读取 policies.json 失败: %v", err)
	}
	var parsed struct {
		Policies map[string]interface{} `json:"policies"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("解析 policies.json 失败: %v", err)
	}
	if parsed.Policies["DisableDefaultBrowserAgent"] != true {
		t.Errorf("policies.json 必须将 DisableDefaultBrowserAgent 设为 true")
	}
	if parsed.Policies["DisableAppUpdate"] != true {
		t.Errorf("policies.json 必须将 DisableAppUpdate 设为 true")
	}
	prefsMap, ok := parsed.Policies["Preferences"].(map[string]interface{})
	if !ok || prefsMap["browser.startup.page"] == nil {
		t.Errorf("policies.json 必须配置 locked Preferences 会话恢复")
	}

	// 触发本地内置内核全量净化
	SanitizeFirefoxKernel("../data/kernels/firefox_156")
	SanitizeFirefoxKernel("../data/kernels/firefox_156/firefox")
	SanitizeFirefoxKernel("../data/kernels/firefox_140")
	SanitizeFirefoxKernel("../data/kernels/firefox_140/firefox")

	// 3. 验证侵入性程序精简切除
	for _, tool := range []string{"default-browser-agent.exe", "updater.exe", "crashreporter.exe", "pingsender.exe"} {
		p := filepath.Join(testKernelDir, tool)
		_ = os.WriteFile(p, []byte("fake_binary"), 0755)
	}
	PurgeFirefoxInvasiveBinaries(testKernelDir)
	for _, tool := range []string{"default-browser-agent.exe", "updater.exe", "crashreporter.exe", "pingsender.exe"} {
		p := filepath.Join(testKernelDir, tool)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("PurgeFirefoxInvasiveBinaries 未能彻底剔除侵入程序: %s", tool)
		}
	}
}

func TestCrossPlatformKernelMatrix(t *testing.T) {
	// 验证当前平台的平台标识与直链动态绑定
	currentPlatform := getCfTPlatform()
	if runtime.GOOS == "windows" {
		if currentPlatform != "win64" {
			t.Errorf("Windows 环境下 CfT 平台应为 win64, 实际为: %s", currentPlatform)
		}
	} else if runtime.GOOS == "darwin" {
		if runtime.GOARCH == "arm64" && currentPlatform != "mac-arm64" {
			t.Errorf("macOS ARM64 环境下 CfT 平台应为 mac-arm64, 实际为: %s", currentPlatform)
		} else if runtime.GOARCH == "amd64" && currentPlatform != "mac-x64" {
			t.Errorf("macOS AMD64 环境下 CfT 平台应为 mac-x64, 实际为: %s", currentPlatform)
		}
	}

	// 验证 Firefox 直链
	ffURL := getFirefoxDownloadURL("156.0")
	if runtime.GOOS == "windows" {
		if !strings.Contains(ffURL, "firefox-win64.zip") {
			t.Errorf("Windows 下 Firefox 直链必须为 win64.zip: %s", ffURL)
		}
		if strings.Contains(ffURL, "mac") {
			t.Errorf("Windows 下 Firefox 直链绝不能包含 mac: %s", ffURL)
		}
	} else if runtime.GOOS == "darwin" {
		if !strings.Contains(ffURL, "mac") {
			t.Errorf("macOS 下 Firefox 直链必须包含 mac: %s", ffURL)
		}
		if strings.Contains(ffURL, "win64") {
			t.Errorf("macOS 下 Firefox 直链绝不能包含 win64: %s", ffURL)
		}
	}

	// 验证 Safari 拟态与原生隔离
	tempDir := t.TempDir()
	kernels := GetAvailableKernelsWithStatus(context.Background(), tempDir)
	hasSafariEmulated := false
	for _, k := range kernels {
		if k.Type == "safari" && k.Milestone == "emulated" {
			hasSafariEmulated = true
		}
	}
	if runtime.GOOS == "windows" && !hasSafariEmulated {
		t.Errorf("Windows 环境下必须具备 Safari WebKit 拟态能力")
	} else if runtime.GOOS == "darwin" && hasSafariEmulated {
		t.Errorf("macOS 环境下严禁出现 Safari WebKit 拟态条目 (必须走原生)")
	}
}
