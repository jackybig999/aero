package desk

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// KernelVersionInfo 内核版本元数据
type KernelVersionInfo struct {
	Type        string  `json:"type"`         // "chrome" 或 "firefox"
	Version     string  `json:"version"`      // 如 "156.0"
	Milestone   string  `json:"milestone"`    // 如 "156"
	DownloadURL string  `json:"download_url"` // 官方直链
	IsInstalled bool    `json:"is_installed"`
	Status      string  `json:"status"`     // "ready", "corrupted", "not_downloaded"
	StatusMsg   string  `json:"status_msg"` // 状态详情描述
	LocalPath   string  `json:"local_path"`
	SizeMB      float64 `json:"size_mb"` // 占用磁盘空间 (MB)
}

// LocalBrowserPath 本地浏览器检测结果
type LocalBrowserPath struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// ChromeInstance 活跃的 Chrome 进程实例
type ChromeInstance struct {
	ProfileID   int64         `json:"profile_id"`
	PID         int           `json:"pid"`
	CDPPort     int           `json:"cdp_port"`
	UserDataDir string        `json:"user_data_dir"`
	Cmd         *exec.Cmd     `json:"-"`
	ExitChan    chan struct{} `json:"-"`
	mu          sync.Mutex    `json:"-"`
}

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

// SafariInstance 活跃的 Safari / WebKit 实例
type SafariInstance struct {
	ProfileID  int64           `json:"profile_id"`
	PID        int             `json:"pid"`
	Mode       string          `json:"mode"` // "emulation" 或 "webkit_sandbox"
	ProfileDir string          `json:"profile_dir"`
	ChromeInst *ChromeInstance `json:"-"`
	Cmd        *exec.Cmd       `json:"-"`
	ExitChan   chan struct{}   `json:"-"`
	mu         sync.Mutex      `json:"-"`
}

// FirefoxPolicies 定义 Firefox 企业级顶层硬核策略结构
type FirefoxPolicies struct {
	Policies map[string]interface{} `json:"policies"`
}

var (
	activeInstances   = make(map[int64]*ChromeInstance)
	activeInstancesMu sync.RWMutex
	cachedChromePath  string
	cachedChromeMu    sync.RWMutex

	activeFirefox   = make(map[int64]*FirefoxInstance)
	activeFirefoxMu sync.RWMutex

	activeSafari   = make(map[int64]*SafariInstance)
	activeSafariMu sync.RWMutex

	kernelProgressMap = make(map[string]int)
	kernelProgressMu  sync.RWMutex
)

// NormalizeLocale 标准化国家/地区语言标记
func NormalizeLocale(loc string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return "en-US"
	}
	low := strings.ToLower(loc)
	if strings.HasPrefix(low, "zh") {
		if strings.Contains(low, "tw") || strings.Contains(low, "hant") {
			return "zh-TW"
		}
		if strings.Contains(low, "hk") || strings.Contains(low, "mo") {
			return "zh-HK"
		}
		return "zh-CN"
	}
	if strings.HasPrefix(low, "en") {
		if strings.Contains(low, "gb") || strings.Contains(low, "uk") {
			return "en-GB"
		}
		return "en-US"
	}
	if strings.HasPrefix(low, "ja") {
		return "ja"
	}
	if strings.HasPrefix(low, "de") {
		return "de"
	}
	if strings.HasPrefix(low, "fr") {
		return "fr"
	}
	if strings.HasPrefix(low, "ru") {
		return "ru"
	}
	if strings.HasPrefix(low, "es") {
		return "es"
	}
	if strings.HasPrefix(low, "ko") {
		return "ko"
	}
	if strings.HasPrefix(low, "it") {
		return "it"
	}
	return loc
}

// GetDefaultFingerprintCheckURL 根据语言返回与系统语言同步的指纹环境检测页面
func GetDefaultFingerprintCheckURL(locale string) string {
	low := strings.ToLower(locale)
	if strings.HasPrefix(low, "zh") {
		return "https://whoer.net/zh"
	}
	if strings.HasPrefix(low, "ja") {
		return "https://whoer.net/ja"
	}
	if strings.HasPrefix(low, "ru") {
		return "https://whoer.net/ru"
	}
	if strings.HasPrefix(low, "es") {
		return "https://whoer.net/es"
	}
	if strings.HasPrefix(low, "fr") {
		return "https://whoer.net/fr"
	}
	if strings.HasPrefix(low, "de") {
		return "https://whoer.net/"
	}
	return "https://whoer.net/en"
}

// SetKernelProgress 设置下载进度
func SetKernelProgress(key string, progress int) {
	kernelProgressMu.Lock()
	defer kernelProgressMu.Unlock()
	kernelProgressMap[key] = progress
}

// GetKernelProgress 获取下载进度
func GetKernelProgress(key string) int {
	kernelProgressMu.RLock()
	defer kernelProgressMu.RUnlock()
	return kernelProgressMap[key]
}

// TriggerKernelDownload 后台异步触发内核下载与自动解压
func TriggerKernelDownload(dataDir, kernelType, milestone, dlURL string, onDone func(err error)) {
	key := fmt.Sprintf("%s_%s", kernelType, milestone)

	kernelProgressMu.Lock()
	p := kernelProgressMap[key]
	if p > 0 && p < 100 {
		kernelProgressMu.Unlock()
		if onDone != nil {
			onDone(errors.New("该内核正在下载处理中，请稍候"))
		}
		return
	}
	kernelProgressMap[key] = 1
	kernelProgressMu.Unlock()

	go func() {
		targetDir := filepath.Join(dataDir, "kernels", key)
		err := DownloadAndExtractKernel(context.Background(), dlURL, targetDir, func(percent int) {
			if percent <= 0 {
				percent = 1
			}
			if percent >= 100 {
				percent = 99
			}
			SetKernelProgress(key, percent)
		})

		if err == nil {
			SetKernelProgress(key, 100)
		} else {
			SetKernelProgress(key, -1)
		}

		if onDone != nil {
			onDone(err)
		}
	}()
}

// IsProfileRunning 检查指定 Profile 是否在运行
func IsProfileRunning(profileID int64) bool {
	activeInstancesMu.RLock()
	if inst, ok := activeInstances[profileID]; ok && inst.IsRunning() {
		activeInstancesMu.RUnlock()
		return true
	}
	activeInstancesMu.RUnlock()

	activeFirefoxMu.RLock()
	if ff, ok := activeFirefox[profileID]; ok && ff.IsRunning() {
		activeFirefoxMu.RUnlock()
		return true
	}
	activeFirefoxMu.RUnlock()

	activeSafariMu.RLock()
	if sf, ok := activeSafari[profileID]; ok && sf.IsRunning() {
		activeSafariMu.RUnlock()
		return true
	}
	activeSafariMu.RUnlock()

	return false
}

// StopProfileInstance 停止运行中的指定 Profile 浏览器实例
func StopProfileInstance(profileID int64) error {
	activeInstancesMu.Lock()
	if inst, ok := activeInstances[profileID]; ok {
		_ = inst.Stop()
		delete(activeInstances, profileID)
	}
	activeInstancesMu.Unlock()

	activeFirefoxMu.Lock()
	if ff, ok := activeFirefox[profileID]; ok {
		_ = ff.Stop()
		delete(activeFirefox, profileID)
	}
	activeFirefoxMu.Unlock()

	activeSafariMu.Lock()
	if sf, ok := activeSafari[profileID]; ok {
		_ = sf.Stop()
		delete(activeSafari, profileID)
	}
	activeSafariMu.Unlock()

	return nil
}

// FindFreePort 瞬间获取系统分配的空闲可用端口
func FindFreePort(basePort int) (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port, nil
	}
	for port := basePort; port < basePort+100; port++ {
		ln2, err2 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err2 == nil {
			_ = ln2.Close()
			return port, nil
		}
	}
	return basePort, nil
}

func configureChromeUserDataLocale(userDataDir string, fpCfg *FingerprintConfig) (string, string) {
	rawLang := ""
	if fpCfg != nil && len(fpCfg.Languages) > 0 {
		rawLang = strings.TrimSpace(fpCfg.Languages[0])
	}
	if rawLang == "" || strings.EqualFold(rawLang, "system") {
		rawLang = GetHostSystemLocale()
	}

	appLocale := "en-US"
	low := strings.ToLower(rawLang)
	if strings.HasPrefix(low, "zh") {
		if strings.EqualFold(rawLang, "zh-TW") {
			appLocale = "zh-TW"
		} else if strings.EqualFold(rawLang, "zh-HK") {
			appLocale = "zh-HK"
		} else {
			appLocale = "zh-CN"
		}
	} else if strings.HasPrefix(low, "en") {
		if strings.EqualFold(rawLang, "en-GB") {
			appLocale = "en-GB"
		} else {
			appLocale = "en-US"
		}
	} else if strings.HasPrefix(low, "ja") {
		appLocale = "ja"
	} else if strings.HasPrefix(low, "de") {
		appLocale = "de"
	} else if strings.HasPrefix(low, "fr") {
		appLocale = "fr"
	} else if strings.HasPrefix(low, "es") {
		appLocale = "es"
	} else if strings.HasPrefix(low, "ru") {
		appLocale = "ru"
	} else if strings.HasPrefix(low, "ko") {
		appLocale = "ko"
	} else if strings.HasPrefix(low, "it") {
		appLocale = "it"
	} else {
		appLocale = NormalizeLocale(rawLang)
	}

	var validLangs []string
	if fpCfg != nil {
		for _, l := range fpCfg.Languages {
			l = strings.TrimSpace(l)
			if l != "" && !strings.EqualFold(l, "system") {
				validLangs = append(validLangs, l)
			}
		}
	}
	if len(validLangs) == 0 {
		validLangs = append(validLangs, appLocale)
		if strings.HasPrefix(appLocale, "zh") {
			validLangs = append(validLangs, "zh")
		} else if !strings.HasPrefix(appLocale, "en") {
			validLangs = append(validLangs, "en")
		}
	} else if !strings.Contains(strings.Join(validLangs, ","), appLocale) {
		validLangs = append([]string{appLocale}, validLangs...)
	}

	acceptLangs := strings.Join(validLangs, ",")

	localStatePath := filepath.Join(userDataDir, "Local State")
	var localState map[string]interface{}
	if data, err := os.ReadFile(localStatePath); err == nil {
		_ = json.Unmarshal(data, &localState)
	}
	if localState == nil {
		localState = make(map[string]interface{})
	}
	intlMap, _ := localState["intl"].(map[string]interface{})
	if intlMap == nil {
		intlMap = make(map[string]interface{})
	}
	intlMap["app_locale"] = appLocale
	intlMap["selected_languages"] = acceptLangs
	localState["intl"] = intlMap
	if b, err := json.MarshalIndent(localState, "", "  "); err == nil {
		_ = os.WriteFile(localStatePath, b, 0644)
	}

	defaultDir := filepath.Join(userDataDir, "Default")
	_ = os.MkdirAll(defaultDir, 0755)

	return appLocale, acceptLangs
}

// LaunchChrome 启动隔离的 Chrome 实例
func LaunchChrome(chromePath, dataDir string, profileID int64, proxyCfg *ProxyConfig, fpCfg *FingerprintConfig, startupURL string, extraFlags []string) (*ChromeInstance, error) {
	activeInstancesMu.Lock()
	if inst, exists := activeInstances[profileID]; exists && inst.IsRunning() {
		activeInstancesMu.Unlock()
		return inst, fmt.Errorf("Profile %d 已经在运行中 (PID: %d)", profileID, inst.PID)
	}
	activeInstancesMu.Unlock()

	if chromePath == "" {
		cachedChromeMu.RLock()
		cand := cachedChromePath
		cachedChromeMu.RUnlock()
		if cand != "" {
			if _, err := os.Stat(cand); err == nil {
				chromePath = cand
			}
		}
	}

	if chromePath == "" {
		kernelsDir := filepath.Join(dataDir, "kernels")
		if entries, err := os.ReadDir(kernelsDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), "chrome") {
					p := LocateDownloadedKernel(filepath.Join(kernelsDir, entry.Name()), "chrome")
					if p != "" {
						chromePath = p
						break
					}
				}
			}
		}

		if chromePath == "" {
			detected := DetectLocalBrowsers()
			for _, b := range detected {
				if b.Type == "chrome" {
					chromePath = b.Path
					break
				}
			}
		}

		if chromePath == "" {
			return nil, fmt.Errorf("未找到可用 Chrome 内核，请在 [内核管理] 中点击下载官方内核或安装 Chrome")
		}

		cachedChromeMu.Lock()
		cachedChromePath = chromePath
		cachedChromeMu.Unlock()
	}

	cdpPort, err := FindFreePort(9222)
	if err != nil {
		return nil, fmt.Errorf("分配 CDP 端口失败: %w", err)
	}

	profileUserData := filepath.Join(dataDir, "profiles", strconv.FormatInt(profileID, 10), "userdata")
	if err := os.MkdirAll(profileUserData, 0755); err != nil {
		return nil, fmt.Errorf("创建 UserData 目录失败: %w", err)
	}

	_ = os.Remove(filepath.Join(profileUserData, "SingletonLock"))
	_ = os.Remove(filepath.Join(profileUserData, "lockfile"))

	appLocale, acceptLang := configureChromeUserDataLocale(profileUserData, fpCfg)

	args := []string{
		"--no-sandbox",
		fmt.Sprintf("--remote-debugging-port=%d", cdpPort),
		fmt.Sprintf("--user-data-dir=%s", profileUserData),
		fmt.Sprintf("--lang=%s", appLocale),
		fmt.Sprintf("--accept-lang=%s", acceptLang),
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-blink-features=AutomationControlled",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--disable-session-crashed-bubble",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-domain-reliability",
		"--disable-client-side-phishing-detection",
		"--disable-sync",
		"--enable-features=Translate",
		"--disable-default-apps",
		"--no-pings",
		"--renderer-process-limit=3",
		"--disable-features=AudioServiceOutOfProcess,OptimizationHints,MediaRouter",
	}

	var fpScript string
	if fpCfg != nil {
		if fpCfg.ScreenWidth > 0 && fpCfg.ScreenHeight > 0 {
			args = append(args, fmt.Sprintf("--window-size=%d,%d", fpCfg.ScreenWidth, fpCfg.ScreenHeight))
		}
		if fpCfg.UserAgent != "" {
			args = append(args, fmt.Sprintf("--user-agent=%s", fpCfg.UserAgent))
		}

		// 方案双轨保障 (a): 自动生成内嵌扩展并通过 --load-extension 挂载注入，最早时机抹除真实指纹
		fpScript = BuildFingerprintScript(fpCfg)
		extDir := filepath.Join(profileUserData, "aero_fp_ext")
		if err := BuildChromeFingerprintExtension(extDir, fpScript); err == nil {
			args = append(args, fmt.Sprintf("--load-extension=%s", extDir))
		}
	}

	if proxyCfg != nil && proxyCfg.Enabled && proxyCfg.Host != "" {
		args = append(args, proxyCfg.ChromeProxyArg())
	}

	if startupURL != "" {
		args = append(args, startupURL)
	} else {
		args = append(args, "--restore-last-session")
	}

	if len(extraFlags) > 0 {
		args = append(args, extraFlags...)
	}

	cmd := exec.Command(chromePath, args...)
	if fpCfg != nil && fpCfg.Timezone != "" {
		cmd.Env = append(os.Environ(), "TZ="+fpCfg.Timezone)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 Chrome 进程失败: %w", err)
	}

	time.Sleep(60 * time.Millisecond)
	if cmd.Process == nil {
		return nil, errors.New("Chrome 进程启动后异常退出")
	}

	inst := &ChromeInstance{
		ProfileID:   profileID,
		PID:         cmd.Process.Pid,
		CDPPort:     cdpPort,
		UserDataDir: profileUserData,
		Cmd:         cmd,
		ExitChan:    make(chan struct{}),
	}

	activeInstancesMu.Lock()
	activeInstances[profileID] = inst
	activeInstancesMu.Unlock()

	// 方案双轨保障 (b): 若 CDP 端口就绪，调用 CDP 方法 Page.addScriptToEvaluateOnNewDocument 注册注入
	if fpScript != "" {
		go func() {
			if err := inst.CheckCDPReady(4 * time.Second); err == nil {
				for retry := 0; retry < 3; retry++ {
					if err := RegisterCDPFingerprintScript(inst.CDPPort, fpScript); err == nil {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
			}
		}()
	}

	go func() {
		_ = cmd.Wait()
		close(inst.ExitChan)
		activeInstancesMu.Lock()
		delete(activeInstances, profileID)
		activeInstancesMu.Unlock()
	}()

	return inst, nil
}

// IsRunning 检查实例是否仍在运行
func (c *ChromeInstance) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Cmd == nil || c.Cmd.Process == nil {
		return false
	}
	return isProcessAlive(c.PID)
}

// Stop 停止 Chrome 实例
func (c *ChromeInstance) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Cmd != nil && c.Cmd.Process != nil {
		err := GracefulStopPID(c.PID, 1200*time.Millisecond)
		_ = os.Remove(filepath.Join(c.UserDataDir, "SingletonLock"))
		_ = os.Remove(filepath.Join(c.UserDataDir, "SingletonCookie"))
		_ = os.Remove(filepath.Join(c.UserDataDir, "SingletonSocket"))
		return err
	}
	return nil
}

// CheckCDPReady 轮询 CDP 调试端点是否就绪
func (c *ChromeInstance) CheckCDPReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://127.0.0.1:%d/json/version", c.CDPPort)
	client := &http.Client{Timeout: 500 * time.Millisecond}

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				var v map[string]interface{}
				_ = json.NewDecoder(resp.Body).Decode(&v)
				resp.Body.Close()
				return nil
			}
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("等待 CDP 端口 %d 超时", c.CDPPort)
}

// GetWebSocketDebuggerURL 获取页面或浏览器的 WebSocket 调试端点
func (c *ChromeInstance) GetWebSocketDebuggerURL() (string, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/json/version", c.CDPPort)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var data struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	return data.WebSocketDebuggerURL, nil
}

// GenerateFirefoxPrefs 生成隔离环境专用的 prefs.js
func GenerateFirefoxPrefs(proxyCfg *ProxyConfig, fpCfg *FingerprintConfig, marionettePort int) string {
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
		reqLang = GetHostSystemLocale()
	}
	reqLang = NormalizeLocale(reqLang)

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

	sb.WriteString("user_pref(\"browser.startup.page\", 3);\n")
	sb.WriteString("user_pref(\"browser.sessionstore.resume_from_crash\", true);\n")
	sb.WriteString("user_pref(\"browser.sessionstore.max_resumed_crashes\", -1);\n")
	sb.WriteString("user_pref(\"browser.sessionstore.restore_on_demand\", false);\n")
	sb.WriteString("user_pref(\"browser.sessionstore.interval\", 10000);\n")

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
	sb.WriteString("user_pref(\"xpinstall.signatures.required\", false);\n")
	sb.WriteString("user_pref(\"extensions.autoDisableScopes\", 0);\n")
	sb.WriteString("user_pref(\"extensions.enabledScopes\", 15);\n")

	if fpCfg != nil {
		if fpCfg.Platform != "" {
			sb.WriteString(fmt.Sprintf("user_pref(\"general.platform.override\", \"%s\");\n", fpCfg.Platform))
		}
		if fpCfg.HardwareConcurrency > 0 {
			sb.WriteString(fmt.Sprintf("user_pref(\"dom.maxHardwareConcurrency\", %d);\n", fpCfg.HardwareConcurrency))
		}
	}

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
func LaunchFirefox(firefoxPath, dataDir string, profileID int64, proxyCfg *ProxyConfig, fpCfg *FingerprintConfig, startupURL string) (*FirefoxInstance, error) {
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

	prefsJsPath := filepath.Join(profileDir, "prefs.js")
	if err := os.WriteFile(prefsJsPath, []byte(prefsContent), 0644); err != nil {
		return nil, fmt.Errorf("挂载 prefs.js 失败: %w", err)
	}

	// 动态注入 Firefox 指纹对抗扩展
	if fpCfg != nil {
		extDir := filepath.Join(profileDir, "extensions")
		_ = os.MkdirAll(extDir, 0755)
		fpScript := BuildFingerprintScript(fpCfg)
		_, _ = BuildFirefoxFingerprintExtension(extDir, fpScript)
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

// Stop 停止 Firefox 实例
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

// BuildChromeFingerprintExtension 动态生成 Chrome 内嵌扩展目录 (manifest v3, run_at: document_start, all_frames: true, match_about_blank: true)
func BuildChromeFingerprintExtension(targetDir string, jsCode string) error {
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}

	manifest := `{
  "manifest_version": 3,
  "name": "AERO Fingerprint Shield",
  "version": "1.0.0",
  "description": "Native embedded fingerprint defense extension",
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_start",
      "all_frames": true,
      "match_about_blank": true,
      "world": "MAIN"
    }
  ]
}`

	if err := os.WriteFile(filepath.Join(targetDir, "manifest.json"), []byte(manifest), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(targetDir, "content.js"), []byte(jsCode), 0644); err != nil {
		return err
	}
	return nil
}

// RegisterCDPFingerprintScript 通过 CDP 接口调用 Page.addScriptToEvaluateOnNewDocument 注入指纹对抗代码
func RegisterCDPFingerprintScript(cdpPort int, script string) error {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json", cdpPort))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var targets []struct {
		Type                 string `json:"type"`
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return err
	}

	var lastErr error
	injected := false
	for _, target := range targets {
		if (target.Type == "page" || target.Type == "other") && target.WebSocketDebuggerURL != "" {
			if err := sendCDPAddScript(target.WebSocketDebuggerURL, script); err != nil {
				lastErr = err
			} else {
				injected = true
			}
		}
	}
	if !injected && lastErr != nil {
		return lastErr
	}
	return nil
}

func sendCDPAddScript(wsURL, script string) error {
	ws, err := websocket.Dial(wsURL, "", "http://127.0.0.1")
	if err != nil {
		return err
	}
	defer ws.Close()

	enableReq := map[string]interface{}{
		"id":     1,
		"method": "Page.enable",
	}
	if err := json.NewEncoder(ws).Encode(enableReq); err != nil {
		return err
	}

	_ = ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var dummy map[string]interface{}
	_ = json.NewDecoder(ws).Decode(&dummy)

	addScriptReq := map[string]interface{}{
		"id":     2,
		"method": "Page.addScriptToEvaluateOnNewDocument",
		"params": map[string]interface{}{
			"source": script,
		},
	}
	if err := json.NewEncoder(ws).Encode(addScriptReq); err != nil {
		return err
	}

	_ = ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_ = json.NewDecoder(ws).Decode(&dummy)

	return nil
}

// BuildFirefoxFingerprintExtension 动态生成 Firefox 注入扩展 (.xpi 及解压扩展目录)
func BuildFirefoxFingerprintExtension(targetDir string, jsCode string) (string, error) {
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return "", err
	}
	xpiPath := filepath.Join(targetDir, "fingerprint_hook.xpi")

	manifest := `{
  "manifest_version": 2,
  "name": "AERO Fingerprint Shield",
  "version": "1.0",
  "applications": {
    "gecko": {
      "id": "fingerprint_hook@aero.local"
    }
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_start",
      "all_frames": true,
      "match_about_blank": true
    }
  ]
}`

	// 1. 生成解压形式的扩展目录 (Firefox 支持直接读取扩展文件夹)
	unpackedDir := filepath.Join(targetDir, "fingerprint_hook@aero.local")
	_ = os.MkdirAll(unpackedDir, 0755)
	_ = os.WriteFile(filepath.Join(unpackedDir, "manifest.json"), []byte(manifest), 0644)
	_ = os.WriteFile(filepath.Join(unpackedDir, "content.js"), []byte(jsCode), 0644)

	// 2. 打包为 .xpi 标准 Zip 包
	out, err := os.Create(xpiPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	w := zip.NewWriter(out)
	defer w.Close()

	f, err := w.Create("manifest.json")
	if err != nil {
		return "", err
	}
	_, _ = f.Write([]byte(manifest))

	f2, err := w.Create("content.js")
	if err != nil {
		return "", err
	}
	_, _ = f2.Write([]byte(jsCode))

	return xpiPath, nil
}

// EnsureFirefoxPolicies 在内核目录下配置 distribution/policies.json
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

// PurgeFirefoxInvasiveBinaries 精简切除所有侵入性程序
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

	for _, sub := range []string{"", "firefox"} {
		macContents := filepath.Join(firefoxDir, sub, "Firefox.app", "Contents", "MacOS")
		if fi, err := os.Stat(macContents); err == nil && fi.IsDir() {
			for _, tool := range []string{"updater.app", "crashreporter.app", "pingsender"} {
				_ = os.RemoveAll(filepath.Join(macContents, tool))
			}
		}
	}
}

// SanitizeFirefoxKernel 综合处理 Firefox 内核目录
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

// LaunchSafari 跨平台启动 Safari 内核沙箱实例
func LaunchSafari(safariPath, dataDir string, profileID int64, proxyCfg *ProxyConfig, fpCfg *FingerprintConfig, startupURL string) (*SafariInstance, error) {
	activeSafariMu.Lock()
	if inst, exists := activeSafari[profileID]; exists && inst.IsRunning() {
		activeSafariMu.Unlock()
		return inst, fmt.Errorf("Safari Profile %d 已经在运行中 (PID: %d)", profileID, inst.PID)
	}
	activeSafariMu.Unlock()

	if fpCfg == nil {
		fpCfg = GenerateFingerprintConfig("", "US", "safari", "17.5")
	} else {
		fpCfg.Platform = "MacIntel"
		if fpCfg.UserAgent == "" || strings.Contains(fpCfg.UserAgent, "Chrome") {
			fpCfg.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
		}
		fpCfg.WebGLVendor = "Google Inc. (Apple)"
		fpCfg.WebGLRenderer = "ANGLE (Apple, Apple M2, OpenGL 4.1)"
	}

	// 模式 1: macOS 原生 Safari 沙箱启动
	if runtime.GOOS == "darwin" && (proxyCfg == nil || !proxyCfg.Enabled || proxyCfg.Host == "") {
		realPath := safariPath
		if realPath == "" {
			cand := "/Applications/Safari.app/Contents/MacOS/Safari"
			if _, err := os.Stat(cand); err == nil {
				realPath = cand
			}
		}

		if realPath != "" {
			profileDir := filepath.Join(dataDir, "profiles", strconv.FormatInt(profileID, 10), "safari_data")
			_ = os.MkdirAll(profileDir, 0755)

			reqLang := GetHostSystemLocale()
			if len(fpCfg.Languages) > 0 && fpCfg.Languages[0] != "" && !strings.EqualFold(fpCfg.Languages[0], "system") {
				reqLang = NormalizeLocale(fpCfg.Languages[0])
			}

			var args []string
			args = append(args, "-AppleLanguages", fmt.Sprintf("('%s')", reqLang))
			args = append(args, "-AppleLocale", strings.ReplaceAll(reqLang, "-", "_"))

			if startupURL != "" {
				args = append(args, startupURL)
			}

			cmd := exec.Command(realPath, args...)
			cmd.Env = append(os.Environ(), "HOME="+profileDir)
			if fpCfg.Timezone != "" {
				cmd.Env = append(cmd.Env, "TZ="+fpCfg.Timezone)
			}

			if err := cmd.Start(); err == nil && cmd.Process != nil {
				inst := &SafariInstance{
					ProfileID:  profileID,
					PID:        cmd.Process.Pid,
					Mode:       "webkit_sandbox",
					ProfileDir: profileDir,
					Cmd:        cmd,
					ExitChan:   make(chan struct{}),
				}
				activeSafariMu.Lock()
				activeSafari[profileID] = inst
				activeSafariMu.Unlock()

				go func() {
					_ = cmd.Wait()
					close(inst.ExitChan)
					activeSafariMu.Lock()
					delete(activeSafari, profileID)
					activeSafariMu.Unlock()
				}()

				return inst, nil
			}
		}
	}

	// 模式 2: WebKit 深度拟态伪装模式
	cInst, err := LaunchChrome("", dataDir, profileID, proxyCfg, fpCfg, startupURL, nil)
	if err != nil {
		return nil, fmt.Errorf("启动 Safari 拟态内核失败: %w", err)
	}

	inst := &SafariInstance{
		ProfileID:  profileID,
		PID:        cInst.PID,
		Mode:       "emulation",
		ProfileDir: cInst.UserDataDir,
		ChromeInst: cInst,
		ExitChan:   make(chan struct{}),
	}

	activeSafariMu.Lock()
	activeSafari[profileID] = inst
	activeSafariMu.Unlock()

	go func() {
		<-cInst.ExitChan
		close(inst.ExitChan)
		activeSafariMu.Lock()
		delete(activeSafari, profileID)
		activeSafariMu.Unlock()
	}()

	return inst, nil
}

// IsRunning 检查 Safari 是否在运行
func (s *SafariInstance) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ChromeInst != nil {
		return s.ChromeInst.IsRunning()
	}
	if s.Cmd == nil || s.Cmd.Process == nil {
		return false
	}
	return isProcessAlive(s.PID)
}

// Stop 停止 Safari 实例
func (s *SafariInstance) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ChromeInst != nil {
		return s.ChromeInst.Stop()
	}
	if s.Cmd != nil && s.Cmd.Process != nil {
		return GracefulStopPID(s.PID, 1200*time.Millisecond)
	}
	return nil
}

// CleanKernelDir 强制安全清理内核目录
func CleanKernelDir(targetDir string) error {
	if targetDir == "" {
		return nil
	}
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		return nil
	}

	if runtime.GOOS == "windows" {
		abs, err := filepath.Abs(targetDir)
		if err == nil {
			psCmd := fmt.Sprintf(`Get-Process | Where-Object { $_.Path -and ($_.Path.ToLower().StartsWith('%s')) } | Stop-Process -Force -ErrorAction SilentlyContinue`, strings.ToLower(strings.ReplaceAll(abs, `'`, `''`)))
			_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).Run()
		}
	}

	time.Sleep(100 * time.Millisecond)

	var lastErr error
	for i := 0; i < 4; i++ {
		lastErr = os.RemoveAll(targetDir)
		if lastErr == nil || os.IsNotExist(lastErr) {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return lastErr
}

// DeleteKernel 彻底清理删除指定的便携内核目录及运行锁
func DeleteKernel(dataDir, kernelType, milestone string) error {
	key := fmt.Sprintf("%s_%s", kernelType, milestone)
	targetDir := filepath.Join(dataDir, "kernels", key)
	SetKernelProgress(key, 0)
	return CleanKernelDir(targetDir)
}

// CleanInstallerArtifacts 仅清理项目内核目录下的安装器残留文件
func CleanInstallerArtifacts(targetDir string) {
	junkList := []string{
		"maintenanceservice.exe",
		"maintenanceservice_installer.exe",
		"install.log",
		"installation_telemetry.json",
		"uninstall",
		"desktop-launcher",
		"setup.tmp.exe",
		"download.tmp.zip",
		"setup.exe",
		"package.tmp",
	}
	for _, j := range junkList {
		_ = os.RemoveAll(filepath.Join(targetDir, j))
	}
}

// ValidateKernelDir 深度检测内核目录的完整性、就绪状态与实际磁盘占用
func ValidateKernelDir(targetDir, kernelType string) (status string, execPath string, sizeMB float64) {
	info, err := os.Stat(targetDir)
	if err != nil || !info.IsDir() {
		return "not_downloaded", "", 0
	}

	var totalBytes int64
	fileCount := 0
	_ = filepath.Walk(targetDir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && !fi.IsDir() {
			totalBytes += fi.Size()
			fileCount++
		}
		return nil
	})

	if fileCount == 0 {
		return "not_downloaded", "", 0
	}

	sizeMB = float64(totalBytes) / (1024 * 1024)

	execPath = LocateDownloadedKernel(targetDir, kernelType)
	if execPath != "" && isKernelExecutableValid(execPath, kernelType) {
		return "ready", execPath, sizeMB
	}

	return "corrupted", "", sizeMB
}

// LocateDownloadedKernel 查找解压后的内核可执行文件真实路径
func LocateDownloadedKernel(targetDir, kernelType string) string {
	if kernelType == "safari" {
		if runtime.GOOS == "darwin" {
			cand := "/Applications/Safari.app/Contents/MacOS/Safari"
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
			return "/Applications/Safari.app"
		}
		return LocateDownloadedKernel(targetDir, "chrome")
	}

	var possibleSubpaths []string
	if kernelType == "chrome" {
		if runtime.GOOS == "windows" {
			possibleSubpaths = []string{
				filepath.Join(targetDir, "chrome-win64", "chrome.exe"),
				filepath.Join(targetDir, "chrome.exe"),
			}
		} else if runtime.GOOS == "darwin" {
			possibleSubpaths = []string{
				filepath.Join(targetDir, "chrome-mac-arm64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
				filepath.Join(targetDir, "chrome-mac-x64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
				filepath.Join(targetDir, "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
			}
		} else {
			possibleSubpaths = []string{
				filepath.Join(targetDir, "chrome-linux64", "chrome"),
				filepath.Join(targetDir, "chrome"),
			}
		}
	} else if kernelType == "firefox" {
		if runtime.GOOS == "windows" {
			possibleSubpaths = []string{
				filepath.Join(targetDir, "core", "firefox.exe"),
				filepath.Join(targetDir, "firefox", "firefox.exe"),
				filepath.Join(targetDir, "firefox.exe"),
			}
		} else if runtime.GOOS == "darwin" {
			possibleSubpaths = []string{
				filepath.Join(targetDir, "firefox", "Firefox.app", "Contents", "MacOS", "firefox"),
				filepath.Join(targetDir, "Firefox.app", "Contents", "MacOS", "firefox"),
				filepath.Join(targetDir, "core", "Firefox.app", "Contents", "MacOS", "firefox"),
			}
		} else {
			possibleSubpaths = []string{
				filepath.Join(targetDir, "firefox", "firefox"),
				filepath.Join(targetDir, "firefox"),
			}
		}
	}

	for _, p := range possibleSubpaths {
		if isKernelExecutableValid(p, kernelType) {
			return p
		}
	}

	var found string
	_ = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if !info.IsDir() {
			base := strings.ToLower(info.Name())
			if (kernelType == "chrome" && (base == "chrome.exe" || base == "chrome" || strings.Contains(base, "testing"))) ||
				(kernelType == "firefox" && (base == "firefox.exe" || base == "firefox")) {
				if isKernelExecutableValid(path, kernelType) {
					found = path
					return filepath.SkipDir
				}
			}
		}
		return nil
	})
	return found
}

// GetAvailableKernelsWithStatus 返回包含深度检测状态、磁盘空间占用与本地路径的内核完整清单
func GetAvailableKernelsWithStatus(ctx context.Context, dataDir string) []KernelVersionInfo {
	var list []KernelVersionInfo

	locals := DetectLocalBrowsers()
	for _, b := range locals {
		list = append(list, KernelVersionInfo{
			Type:        b.Type,
			Version:     "本机安装版",
			Milestone:   "local",
			IsInstalled: true,
			Status:      "ready",
			StatusMsg:   "本机系统浏览器",
			LocalPath:   b.Path,
		})
	}

	if runtime.GOOS == "windows" {
		list = append(list, KernelVersionInfo{
			Type:        "safari",
			Version:     "WebKit 拟态",
			Milestone:   "emulated",
			IsInstalled: true,
			Status:      "ready",
			StatusMsg:   "WebKit 拟态伪装 (基于 Chrome 内核)",
			LocalPath:   "emulated",
		})
	}

	officials := GetFastOfficialKernels()
	allPortableMap := make(map[string]KernelVersionInfo)

	for _, k := range officials {
		key := fmt.Sprintf("%s_%s", k.Type, k.Milestone)
		targetDir := filepath.Join(dataDir, "kernels", key)
		status, loc, sizeMB := ValidateKernelDir(targetDir, k.Type)
		k.Status = status
		k.SizeMB = sizeMB
		if status == "ready" {
			k.IsInstalled = true
			k.LocalPath = loc
			k.StatusMsg = fmt.Sprintf("已就绪 (%.1f MB)", sizeMB)
		} else if status == "corrupted" {
			k.IsInstalled = false
			k.LocalPath = ""
			k.StatusMsg = fmt.Sprintf("核心组件残缺或损坏 (%.1f MB)", sizeMB)
		} else {
			k.IsInstalled = false
			k.LocalPath = ""
			k.StatusMsg = "未下载"
		}
		allPortableMap[key] = k
	}

	kernelsDir := filepath.Join(dataDir, "kernels")
	if entries, err := os.ReadDir(kernelsDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			name := entry.Name()
			parts := strings.SplitN(name, "_", 2)
			if len(parts) != 2 {
				continue
			}
			kType, kMilestone := parts[0], parts[1]
			if kType != "chrome" && kType != "firefox" {
				continue
			}

			targetDir := filepath.Join(kernelsDir, name)
			status, loc, sizeMB := ValidateKernelDir(targetDir, kType)
			existing, ok := allPortableMap[name]
			if !ok {
				existing = KernelVersionInfo{
					Type:      kType,
					Version:   kMilestone,
					Milestone: kMilestone,
				}
			}
			existing.IsInstalled = (status == "ready")
			existing.Status = status
			existing.SizeMB = sizeMB
			existing.LocalPath = loc
			if status == "ready" {
				existing.StatusMsg = fmt.Sprintf("已就绪 (%.1f MB)", sizeMB)
			} else if status == "corrupted" {
				existing.StatusMsg = fmt.Sprintf("核心组件残缺或损坏 (%.1f MB)", sizeMB)
			} else {
				existing.StatusMsg = "未下载"
			}
			allPortableMap[name] = existing
		}
	}

	portablesByType := make(map[string][]KernelVersionInfo)
	for _, k := range allPortableMap {
		portablesByType[k.Type] = append(portablesByType[k.Type], k)
	}

	for _, kType := range []string{"chrome", "firefox"} {
		items := portablesByType[kType]
		sort.SliceStable(items, func(i, j int) bool {
			mi, _ := strconv.Atoi(items[i].Milestone)
			mj, _ := strconv.Atoi(items[j].Milestone)
			if mi != mj {
				return mi > mj
			}
			return items[i].Version > items[j].Version
		})
		limit := 2
		if len(items) < limit {
			limit = len(items)
		}
		list = append(list, items[:limit]...)
	}

	sort.SliceStable(list, func(i, j int) bool {
		score := func(k KernelVersionInfo) int {
			if k.Status == "ready" || k.IsInstalled {
				if k.Milestone != "local" {
					return 0
				}
				return 1
			}
			if k.Status == "corrupted" {
				return 2
			}
			return 3
		}
		si := score(list[i])
		sj := score(list[j])
		if si != sj {
			return si < sj
		}
		if list[i].Type != list[j].Type {
			typeOrder := map[string]int{"chrome": 1, "firefox": 2, "safari": 3}
			oI := typeOrder[list[i].Type]
			if oI == 0 {
				oI = 99
			}
			oJ := typeOrder[list[j].Type]
			if oJ == 0 {
				oJ = 99
			}
			return oI < oJ
		}
		mI, errI := strconv.Atoi(list[i].Milestone)
		mJ, errJ := strconv.Atoi(list[j].Milestone)
		if errI == nil && errJ == nil && mI != mJ {
			return mI > mJ
		}
		return list[i].Milestone > list[j].Milestone
	})

	return list
}
