package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/config"
)

// FirefoxInstance 活跃的 Firefox 实例
type FirefoxInstance struct {
	ProfileID      int64         `json:"profile_id"`
	PID            int           `json:"pid"`
	MarionettePort int           `json:"marionette_port"`
	ProfileDir     string        `json:"profile_dir"`
	Cmd            *exec.Cmd     `json:"-"`
	ExitChan       chan struct{} `json:"-"`
	mu             sync.Mutex    `json:"-"`
}

var (
	activeFirefox   = make(map[int64]*FirefoxInstance)
	activeFirefoxMu sync.RWMutex
)

// GenerateFirefoxPrefs 生成隔离环境专用的 prefs.js
func GenerateFirefoxPrefs(proxyCfg *proxy.ProxyConfig, fpCfg *fingerprint.FingerprintConfig, marionettePort int) string {
	var sb strings.Builder
	sb.WriteString("// Fingerprint Browser Generated Prefs\n")
	sb.WriteString("user_pref(\"browser.shell.checkDefaultBrowser\", false);\n")
	sb.WriteString("user_pref(\"default-browser-agent.enabled\", false);\n")
	sb.WriteString("user_pref(\"app.update.enabled\", false);\n")
	sb.WriteString("user_pref(\"app.update.auto\", false);\n")
	sb.WriteString("user_pref(\"app.update.background.scheduling.enabled\", false);\n")
	sb.WriteString("user_pref(\"app.update.service.enabled\", false);\n")
	sb.WriteString("user_pref(\"browser.startup.homepage_override.mstone\", \"ignore\");\n")
	sb.WriteString("user_pref(\"toolkit.telemetry.enabled\", false);\n")
	sb.WriteString("user_pref(\"browser.newtabpage.activity-stream.telemetry\", false);\n")
	sb.WriteString("user_pref(\"toolkit.telemetry.bhrPing.enabled\", false);\n")
	sb.WriteString("user_pref(\"toolkit.telemetry.shutdownPingSender.enabled\", false);\n")
	sb.WriteString("user_pref(\"dom.webdriver.enabled\", false);\n")
	sb.WriteString("user_pref(\"browser.safebrowsing.malware.enabled\", false);\n")
	sb.WriteString("user_pref(\"browser.safebrowsing.phishing.enabled\", false);\n")
	sb.WriteString("user_pref(\"browser.safebrowsing.downloads.enabled\", false);\n")
	sb.WriteString("user_pref(\"app.normandy.enabled\", false);\n")
	sb.WriteString("user_pref(\"extensions.update.enabled\", false);\n")
	sb.WriteString("user_pref(\"browser.search.update\", false);\n")
	sb.WriteString("user_pref(\"browser.cache.disk.enable\", false);\n")
	sb.WriteString("user_pref(\"media.peerconnection.enabled\", false);\n")
	sb.WriteString("user_pref(\"media.peerconnection.ice.default_address_only\", true);\n")

	reqLang := ""
	if fpCfg != nil && len(fpCfg.Languages) > 0 {
		reqLang = strings.TrimSpace(fpCfg.Languages[0])
	}
	if reqLang == "" || strings.EqualFold(reqLang, "system") {
		reqLang = config.GetHostSystemLocale()
	}
	reqLang = config.NormalizeLocale(reqLang)

	var acceptLangs []string
	if fpCfg != nil && len(fpCfg.Languages) > 0 {
		for _, l := range fpCfg.Languages {
			l = strings.TrimSpace(l)
			if l != "" && !strings.EqualFold(l, "system") {
				acceptLangs = append(acceptLangs, l)
			}
		}
	}
	if len(acceptLangs) == 0 {
		acceptLangs = append(acceptLangs, reqLang)
		if strings.HasPrefix(reqLang, "zh") {
			acceptLangs = append(acceptLangs, "zh")
		} else if !strings.HasPrefix(reqLang, "en") {
			acceptLangs = append(acceptLangs, "en")
		}
	} else if !strings.Contains(strings.Join(acceptLangs, ","), reqLang) {
		acceptLangs = append([]string{reqLang}, acceptLangs...)
	}

	sb.WriteString(fmt.Sprintf("user_pref(\"intl.locale.requested\", \"%s\");\n", reqLang))
	sb.WriteString(fmt.Sprintf("user_pref(\"intl.accept_languages\", \"%s\");\n", strings.Join(acceptLangs, ", ")))
	sb.WriteString(fmt.Sprintf("user_pref(\"general.useragent.locale\", \"%s\");\n", reqLang))
	sb.WriteString("user_pref(\"intl.regional_prefs.use_os_locales\", true);\n")

	if fpCfg != nil && fpCfg.UserAgent != "" {
		sb.WriteString(fmt.Sprintf("user_pref(\"general.useragent.override\", \"%s\");\n", fpCfg.UserAgent))
	}

	// 会话自动恢复与标签页记忆 (3 = 恢复上次打开的所有窗口与标签页)
	sb.WriteString("user_pref(\"browser.startup.page\", 3);\n")
	sb.WriteString("user_pref(\"browser.sessionstore.resume_from_crash\", true);\n")
	sb.WriteString("user_pref(\"browser.sessionstore.max_resumed_crashes\", -1);\n")
	sb.WriteString("user_pref(\"browser.sessionstore.restore_on_demand\", false);\n")
	sb.WriteString("user_pref(\"browser.sessionstore.interval\", 10000);\n")

	// 彻底禁用退出清理，永久保留 Cookie、历史与登录态
	sb.WriteString("user_pref(\"privacy.clearOnShutdown.cookies\", false);\n")
	sb.WriteString("user_pref(\"privacy.clearOnShutdown.history\", false);\n")
	sb.WriteString("user_pref(\"privacy.clearOnShutdown.sessions\", false);\n")
	sb.WriteString("user_pref(\"privacy.clearOnShutdown.openWindows\", false);\n")
	sb.WriteString("user_pref(\"privacy.clearOnShutdown.offlineApps\", false);\n")
	sb.WriteString("user_pref(\"privacy.sanitize.sanitizeOnShutdown\", false);\n")
	sb.WriteString("user_pref(\"privacy.sanitize.pending\", \"[]\");\n")
	sb.WriteString("user_pref(\"network.cookie.lifetimePolicy\", 0);\n")

	sb.WriteString("user_pref(\"marionette.enabled\", true);\n")
	sb.WriteString(fmt.Sprintf("user_pref(\"marionette.port\", %d);\n", marionettePort))

	if proxyCfg != nil && proxyCfg.Enabled && proxyCfg.Host != "" {
		sb.WriteString("user_pref(\"network.proxy.type\", 1);\n")
		proto := strings.ToLower(proxyCfg.Protocol)
		if proto == "socks5" {
			sb.WriteString(fmt.Sprintf("user_pref(\"network.proxy.socks\", \"%s\");\n", proxyCfg.Host))
			sb.WriteString(fmt.Sprintf("user_pref(\"network.proxy.socks_port\", %d);\n", proxyCfg.Port))
			sb.WriteString("user_pref(\"network.proxy.socks_version\", 5);\n")
			sb.WriteString("user_pref(\"network.proxy.socks_remote_dns\", true);\n")
		} else {
			sb.WriteString(fmt.Sprintf("user_pref(\"network.proxy.http\", \"%s\");\n", proxyCfg.Host))
			sb.WriteString(fmt.Sprintf("user_pref(\"network.proxy.http_port\", %d);\n", proxyCfg.Port))
			sb.WriteString(fmt.Sprintf("user_pref(\"network.proxy.ssl\", \"%s\");\n", proxyCfg.Host))
			sb.WriteString(fmt.Sprintf("user_pref(\"network.proxy.ssl_port\", %d);\n", proxyCfg.Port))
		}
	} else {
		sb.WriteString("user_pref(\"network.proxy.type\", 0);\n")
	}

	return sb.String()
}

// LaunchFirefox 启动隔离的 Firefox 实例
func LaunchFirefox(firefoxPath, dataDir string, profileID int64, proxyCfg *proxy.ProxyConfig, fpCfg *fingerprint.FingerprintConfig, startupURL string) (*FirefoxInstance, error) {
	activeFirefoxMu.Lock()
	if inst, exists := activeFirefox[profileID]; exists && inst.IsRunning() {
		activeFirefoxMu.Unlock()
		return inst, fmt.Errorf("Firefox Profile %d 已经在运行中 (PID: %d)", profileID, inst.PID)
	}
	activeFirefoxMu.Unlock()

	if firefoxPath == "" {
		kernelsDir := filepath.Join(dataDir, "kernels")
		if entries, err := os.ReadDir(kernelsDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), "firefox") {
					p := LocateDownloadedKernel(filepath.Join(kernelsDir, entry.Name()), "firefox")
					if p != "" {
						firefoxPath = p
						break
					}
				}
			}
		}

		if firefoxPath == "" {
			detected := DetectLocalBrowsers()
			for _, b := range detected {
				if b.Type == "firefox" {
					firefoxPath = b.Path
					break
				}
			}
		}

		if firefoxPath == "" {
			return nil, fmt.Errorf("未找到可用 Firefox 内核，请在 [内核管理] 中点击下载官方内核或安装 Firefox")
		}
	}

	// 启动前执行内核级精简与策略锁定，确保无侵入性外部工具并锁死 policies.json
	SanitizeFirefoxKernel(filepath.Dir(firefoxPath))

	mPort, err := FindFreePort(2828)
	if err != nil {
		return nil, fmt.Errorf("分配 Marionette 端口失败: %w", err)
	}

	profileDir := filepath.Join(dataDir, "profiles", strconv.FormatInt(profileID, 10), "firefox_profile")
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return nil, fmt.Errorf("创建 Firefox profile 目录失败: %w", err)
	}

	_ = os.Remove(filepath.Join(profileDir, "parent.lock"))
	_ = os.Remove(filepath.Join(profileDir, "lock"))
	_ = os.Remove(filepath.Join(profileDir, ".parentlock"))

	prefsContent := GenerateFirefoxPrefs(proxyCfg, fpCfg, mPort)
	userJsPath := filepath.Join(profileDir, "user.js")
	if err := os.WriteFile(userJsPath, []byte(prefsContent), 0644); err != nil {
		return nil, fmt.Errorf("写入 user.js 失败: %w", err)
	}

	// 仅在首次创建且 prefs.js 尚不存在时进行基础初始化，严禁覆盖既有已存 Cookies/会话的 prefs.js
	prefsJsPath := filepath.Join(profileDir, "prefs.js")
	if _, err := os.Stat(prefsJsPath); os.IsNotExist(err) {
		_ = os.WriteFile(prefsJsPath, []byte(prefsContent), 0644)
	}

	args := []string{
		"-profile", profileDir,
		"-no-remote",
	}

	if fpCfg != nil && fpCfg.ScreenWidth > 0 && fpCfg.ScreenHeight > 0 {
		args = append(args, "-width", strconv.Itoa(fpCfg.ScreenWidth), "-height", strconv.Itoa(fpCfg.ScreenHeight))
	}

	if startupURL != "" {
		args = append(args, startupURL)
	}

	cmd := exec.Command(firefoxPath, args...)
	if fpCfg != nil && fpCfg.Timezone != "" {
		cmd.Env = append(os.Environ(), "TZ="+fpCfg.Timezone)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 Firefox 进程失败: %w", err)
	}

	inst := &FirefoxInstance{
		ProfileID:      profileID,
		PID:            cmd.Process.Pid,
		MarionettePort: mPort,
		ProfileDir:     profileDir,
		Cmd:            cmd,
		ExitChan:       make(chan struct{}),
	}

	activeFirefoxMu.Lock()
	activeFirefox[profileID] = inst
	activeFirefoxMu.Unlock()

	go func() {
		defer func() {
			close(inst.ExitChan)
			activeFirefoxMu.Lock()
			delete(activeFirefox, profileID)
			activeFirefoxMu.Unlock()
		}()
		parentPID := cmd.Process.Pid
		actualPID := parentPID
		for {
			if actualPID == parentPID {
				if childPID := FindChildProcess(parentPID); childPID > 0 {
					actualPID = childPID
					inst.mu.Lock()
					inst.PID = childPID
					inst.mu.Unlock()
				}
			}
			if isProcessAlive(actualPID) {
				time.Sleep(250 * time.Millisecond)
				continue
			}
			if childPID := FindChildProcess(parentPID); childPID > 0 && isProcessAlive(childPID) {
				actualPID = childPID
				inst.mu.Lock()
				inst.PID = childPID
				inst.mu.Unlock()
				time.Sleep(250 * time.Millisecond)
				continue
			}
			break
		}
	}()

	return inst, nil
}

// IsRunning 检查 Firefox 是否在运行
func (f *FirefoxInstance) IsRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return isProcessAlive(f.PID)
}

// Stop 停止 Firefox 实例 (先软关闭触发保存会话与 Cookies 数据库，超时强杀)
func (f *FirefoxInstance) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = GracefulStopPID(f.PID, 1200*time.Millisecond)
	if f.Cmd != nil && f.Cmd.Process != nil && f.Cmd.Process.Pid != f.PID {
		_ = GracefulStopPID(f.Cmd.Process.Pid, 800*time.Millisecond)
	}
	_ = os.Remove(filepath.Join(f.ProfileDir, "parent.lock"))
	_ = os.Remove(filepath.Join(f.ProfileDir, "lock"))
	_ = os.Remove(filepath.Join(f.ProfileDir, ".parentlock"))
	return nil
}
