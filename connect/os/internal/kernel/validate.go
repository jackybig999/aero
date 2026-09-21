package kernel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

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

	// 严格按内核类型归类，且每种内核仅保留最新的最近 2 代版本 (绝不多列杂乱历史版本)
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

	// 核心排序治理：已下载就绪的排在最上方，残缺损坏居中，未下载靠后
	sort.SliceStable(list, func(i, j int) bool {
		score := func(k KernelVersionInfo) int {
			if k.Status == "ready" || k.IsInstalled {
				if k.Milestone != "local" {
					return 0 // 便携已就绪版最靠前 (第一优先级)
				}
				return 1 // 本机安装版次之 (第二优先级)
			}
			if k.Status == "corrupted" {
				return 2 // 损坏异常居中
			}
			return 3 // 未下载靠后排在最后
		}
		si := score(list[i])
		sj := score(list[j])
		if si != sj {
			return si < sj
		}
		// 同状态下，按内核类型 chrome 在前、firefox 居中、safari 在后
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
		// 同类型下，按大版本号数值降序排列 (较新版本排在前面)
		mI, errI := strconv.Atoi(list[i].Milestone)
		mJ, errJ := strconv.Atoi(list[j].Milestone)
		if errI == nil && errJ == nil && mI != mJ {
			return mI > mJ
		}
		return list[i].Milestone > list[j].Milestone
	})

	return list
}
