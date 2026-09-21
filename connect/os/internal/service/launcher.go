package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/config"
	"aisys/connect/os/internal/kernel"
)

// StartProfile 启动指定环境的浏览器进程
func (s *AppService) StartProfile(id int64) error {
	var kernelType, kernelVersion, fpJSON, notes string
	var proxyID int64
	var lastLaunchedAt sql.NullTime
	err := s.DB.QueryRow(`SELECT kernel_type, kernel_version, notes, proxy_id, fingerprint_config, last_launched_at FROM profiles WHERE id = ?`, id).Scan(&kernelType, &kernelVersion, &notes, &proxyID, &fpJSON, &lastLaunchedAt)
	if err != nil {
		return fmt.Errorf("未找到环境 %d: %w", id, err)
	}

	var fp fingerprint.FingerprintConfig
	_ = json.Unmarshal([]byte(fpJSON), &fp)

	var proxyCfg *proxy.ProxyConfig
	if proxyID > 0 {
		var proto, host, user, pass string
		var port int
		if err := s.DB.QueryRow(`SELECT protocol, host, port, username, password FROM proxies WHERE id = ?`, proxyID).Scan(&proto, &host, &port, &user, &pass); err == nil {
			proxyCfg = &proxy.ProxyConfig{
				Enabled:  true,
				Protocol: proto,
				Host:     host,
				Port:     port,
				Username: user,
				Password: pass,
			}
		}
	}

	hasCustomURL := false
	startupURL := ""
	if strings.Contains(notes, "启动: ") {
		idx := strings.Index(notes, "启动: ")
		cand := strings.TrimSpace(notes[idx+len("启动: "):])
		if strings.Contains(cand, " ") {
			cand = strings.Split(cand, " ")[0]
		}
		isLegacyCheck := strings.Contains(cand, "whoer.net") || strings.Contains(cand, "browserleaks.com") || strings.Contains(cand, "ipinfo.io")
		if cand != "" && !isLegacyCheck {
			startupURL = cand
			hasCustomURL = true
		}
	}

	// 首次启动且未指定自定义 URL 时，打开与当前指纹/系统语言同步的环境检测页供用户初次核对指纹
	// 二次及后续启动，若无自定义 URL，则保持空 URL，以便内核自动恢复上一次打开的所有标签页与 Cookie 会话
	if !hasCustomURL && !lastLaunchedAt.Valid {
		checkLocale := config.GetHostSystemLocale()
		if len(fp.Languages) > 0 && fp.Languages[0] != "" && !strings.EqualFold(fp.Languages[0], "system") {
			checkLocale = fp.Languages[0]
		}
		startupURL = config.GetDefaultFingerprintCheckURL(checkLocale)
	}

	var specificPath string
	if kernelVersion != "" {
		targetDir := filepath.Join(s.DataDir, "kernels", fmt.Sprintf("%s_%s", kernelType, kernelVersion))
		loc := kernel.LocateDownloadedKernel(targetDir, kernelType)
		if loc != "" {
			specificPath = loc
		}
	}

	var launchErr error
	var cInst *kernel.ChromeInstance
	var fInst *kernel.FirefoxInstance
	var sInst *kernel.SafariInstance
	if kernelType == "firefox" {
		fInst, launchErr = kernel.LaunchFirefox(specificPath, s.DataDir, id, proxyCfg, &fp, startupURL)
	} else if kernelType == "safari" {
		sInst, launchErr = kernel.LaunchSafari(specificPath, s.DataDir, id, proxyCfg, &fp, startupURL)
	} else {
		cInst, launchErr = kernel.LaunchChrome(specificPath, s.DataDir, id, proxyCfg, &fp, startupURL, nil)
	}

	if launchErr != nil {
		s.SetProfileStatusCache(id, "error")
		_, _ = s.DB.Exec(`UPDATE profiles SET status = 'error' WHERE id = ?`, id)
		return launchErr
	}

	s.SetProfileStatusCache(id, "running")
	now := time.Now()
	_, _ = s.DB.Exec(`UPDATE profiles SET status = 'running', last_launched_at = ? WHERE id = ?`, now, id)

	go func(profID int64, c *kernel.ChromeInstance, f *kernel.FirefoxInstance, sf *kernel.SafariInstance) {
		if c != nil {
			<-c.ExitChan
		} else if f != nil {
			<-f.ExitChan
		} else if sf != nil {
			<-sf.ExitChan
		}
		s.SetProfileStatusCache(profID, "stopped")
		_, _ = s.DB.Exec(`UPDATE profiles SET status = 'stopped' WHERE id = ?`, profID)
		log.Printf("[INFO] 环境 #%d 浏览器已关闭，状态已自动变更为 [stopped]\n", profID)
	}(id, cInst, fInst, sInst)

	return nil
}

// StopProfile 停止运行中的环境
func (s *AppService) StopProfile(id int64) error {
	s.SetProfileStatusCache(id, "stopped")
	_ = kernel.StopProfileInstance(id)
	_, err := s.DB.Exec(`UPDATE profiles SET status = 'stopped' WHERE id = ?`, id)
	return err
}
