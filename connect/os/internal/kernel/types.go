package kernel

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
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

var (
	kernelProgressMap = make(map[string]int)
	kernelProgressMu  sync.RWMutex
)

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

// TriggerKernelDownload 后台异步触发内核下载与自动解压 (防并发冲突)
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

// IsProfileRunning 检查指定 Profile 是否在运行 (Chrome, Firefox 或 Safari)
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
