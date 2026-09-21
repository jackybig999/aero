package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/domain/proxy"
)

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

var (
	activeInstances   = make(map[int64]*ChromeInstance)
	activeInstancesMu sync.RWMutex
	cachedChromePath  string
	cachedChromeMu    sync.RWMutex
)

// FindFreePort 瞬间获取系统分配的空闲可用端口 (0ms 快速分配，杜绝轮询网络栈耗时)
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

// LaunchChrome 启动隔离的 Chrome 实例
func LaunchChrome(chromePath, dataDir string, profileID int64, proxyCfg *proxy.ProxyConfig, fpCfg *fingerprint.FingerprintConfig, startupURL string, extraFlags []string) (*ChromeInstance, error) {
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
		// 性能与内存极限优化：切除非业务联网与冗余后台子进程
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

	if fpCfg != nil {
		if fpCfg.ScreenWidth > 0 && fpCfg.ScreenHeight > 0 {
			args = append(args, fmt.Sprintf("--window-size=%d,%d", fpCfg.ScreenWidth, fpCfg.ScreenHeight))
		}
		if fpCfg.UserAgent != "" {
			args = append(args, fmt.Sprintf("--user-agent=%s", fpCfg.UserAgent))
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

// Stop 停止 Chrome 实例 (先软关闭触发写入会话与 Cookies，超时强杀)
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
