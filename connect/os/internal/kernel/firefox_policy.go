package kernel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// FirefoxPolicies 定义 Firefox 企业级顶层硬核策略结构
type FirefoxPolicies struct {
	Policies map[string]interface{} `json:"policies"`
}

// EnsureFirefoxPolicies 在内核目录下配置 distribution/policies.json，锁死标签页与会话恢复
func EnsureFirefoxPolicies(firefoxDir string) error {
	if firefoxDir == "" {
		return nil
	}

	distDirs := []string{
		filepath.Join(firefoxDir, "distribution"),
		filepath.Join(firefoxDir, "firefox", "distribution"),
		filepath.Join(firefoxDir, "Firefox.app", "Contents", "Resources", "distribution"),
		filepath.Join(firefoxDir, "firefox", "Firefox.app", "Contents", "Resources", "distribution"),
	}

	policyData := FirefoxPolicies{
		Policies: map[string]interface{}{
			"DisableAppUpdate":           true,
			"DisableDefaultBrowserAgent": true,
			"DisableTelemetry":           true,
			"DontCheckDefaultBrowser":    true,
			"DisableFeedbackCommands":    true,
			"DisablePocket":              true,
			"OverrideFirstRunPage":       "",
			"OverridePostUpdatePage":     "",
			"Preferences": map[string]interface{}{
				"browser.startup.page":                     map[string]interface{}{"Value": 3, "Status": "locked"},
				"browser.sessionstore.resume_from_crash":   map[string]interface{}{"Value": true, "Status": "locked"},
				"browser.sessionstore.max_resumed_crashes": map[string]interface{}{"Value": -1, "Status": "locked"},
				"browser.sessionstore.restore_on_demand":   map[string]interface{}{"Value": false, "Status": "locked"},
				"privacy.clearOnShutdown.cookies":          map[string]interface{}{"Value": false, "Status": "locked"},
				"privacy.clearOnShutdown.history":          map[string]interface{}{"Value": false, "Status": "locked"},
				"privacy.clearOnShutdown.sessions":         map[string]interface{}{"Value": false, "Status": "locked"},
				"privacy.clearOnShutdown.openWindows":      map[string]interface{}{"Value": false, "Status": "locked"},
				"privacy.sanitize.sanitizeOnShutdown":      map[string]interface{}{"Value": false, "Status": "locked"},
			},
		},
	}

	bytes, err := json.MarshalIndent(policyData, "", "  ")
	if err != nil {
		return err
	}

	for _, d := range distDirs {
		parent := filepath.Dir(d)
		if fi, err := os.Stat(parent); err == nil && fi.IsDir() {
			_ = os.MkdirAll(d, 0755)
			_ = os.WriteFile(filepath.Join(d, "policies.json"), bytes, 0644)
		}
	}
	return nil
}

// PurgeFirefoxInvasiveBinaries 精简切除所有侵入性程序与 playwright.cfg 测试专用覆盖配置
func PurgeFirefoxInvasiveBinaries(firefoxDir string) {
	if firefoxDir == "" {
		return
	}
	checkDirs := []string{
		firefoxDir,
		filepath.Join(firefoxDir, "firefox"),
	}

	invasiveTools := []string{
		"default-browser-agent.exe",
		"updater.exe",
		"updater.ini",
		"update-settings.ini",
		"crashreporter.exe",
		"crashreporter.ini",
		"crashhelper.exe",
		"pingsender.exe",
		"maintenanceservice.exe",
		"maintenanceservice_installer.exe",
		"uninstall",
		"playwright.cfg",
		filepath.Join("defaults", "pref", "00-playwright-prefs.js"),
	}

	for _, baseDir := range checkDirs {
		if fi, err := os.Stat(baseDir); err != nil || !fi.IsDir() {
			continue
		}
		for _, tool := range invasiveTools {
			target := filepath.Join(baseDir, tool)
			_ = os.RemoveAll(target)
		}
	}

	// 针对 macOS 下的 Firefox.app 结构进行同等精简
	for _, sub := range []string{"", "firefox"} {
		macContents := filepath.Join(firefoxDir, sub, "Firefox.app", "Contents", "MacOS")
		if fi, err := os.Stat(macContents); err == nil && fi.IsDir() {
			for _, tool := range []string{"updater.app", "crashreporter.app", "pingsender"} {
				_ = os.RemoveAll(filepath.Join(macContents, tool))
			}
		}
	}
}

// SanitizeFirefoxKernel 综合处理 Firefox 内核目录：注入零污染策略并精简多余侵入程序
func SanitizeFirefoxKernel(kernelDir string) {
	if kernelDir == "" {
		return
	}
	root := kernelDir
	if strings.HasSuffix(strings.ToLower(kernelDir), "firefox.exe") {
		root = filepath.Dir(kernelDir)
	}
	PurgeFirefoxInvasiveBinaries(root)
	_ = EnsureFirefoxPolicies(root)
}
