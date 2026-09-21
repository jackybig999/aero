package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/config"
)

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

var (
	activeSafari   = make(map[int64]*SafariInstance)
	activeSafariMu sync.RWMutex
)

// LaunchSafari 跨平台启动 Safari 内核沙箱实例
// - 在 macOS 上: 原生系统检测及沙箱重定向，支持 Apple 语言参数
// - 在 Windows 上: 自动切换为高精度 WebKit/Safari 拟态伪装模式 (注入 Apple Metal / MacIntel / Safari UA)
func LaunchSafari(safariPath, dataDir string, profileID int64, proxyCfg *proxy.ProxyConfig, fpCfg *fingerprint.FingerprintConfig, startupURL string) (*SafariInstance, error) {
	activeSafariMu.Lock()
	if inst, exists := activeSafari[profileID]; exists && inst.IsRunning() {
		activeSafariMu.Unlock()
		return inst, fmt.Errorf("Safari Profile %d 已经在运行中 (PID: %d)", profileID, inst.PID)
	}
	activeSafariMu.Unlock()

	// 确保注入完整的 Safari + macOS 指纹特征
	if fpCfg == nil {
		fpCfg = fingerprint.GenerateFingerprintConfig("", "US", "safari", "17.5")
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

			reqLang := config.GetHostSystemLocale()
			if len(fpCfg.Languages) > 0 && fpCfg.Languages[0] != "" && !strings.EqualFold(fpCfg.Languages[0], "system") {
				reqLang = config.NormalizeLocale(fpCfg.Languages[0])
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

	// 模式 2: WebKit 深度拟态伪装模式 (Windows 工业级标准或带独立代理场景)
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

// IsRunning 检查 Safari 实例是否仍在活跃运行
func (s *SafariInstance) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ChromeInst != nil {
		return s.ChromeInst.IsRunning()
	}
	if s.PID > 0 {
		return isProcessAlive(s.PID)
	}
	return false
}

// Stop 停止 Safari 实例
func (s *SafariInstance) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ChromeInst != nil {
		return s.ChromeInst.Stop()
	}
	if s.Cmd != nil && s.Cmd.Process != nil {
		return GracefulStopProcess(s.Cmd, 1200*time.Millisecond)
	}
	return nil
}
