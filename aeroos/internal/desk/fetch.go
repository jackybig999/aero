package desk

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	cachedOfficialKernels   []KernelVersionInfo
	cachedOfficialKernelsMu sync.RWMutex
	fetchOfficialOnce       sync.Once
)

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func unzipArchive(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("非法路径: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func getCfTPlatform() string {
	if runtime.GOOS == "windows" {
		return "win64"
	} else if runtime.GOOS == "darwin" {
		if runtime.GOARCH == "arm64" {
			return "mac-arm64"
		}
		return "mac-x64"
	}
	return "linux64"
}

func getChromeCfTDownloadURL(version string) string {
	platform := getCfTPlatform()
	return fmt.Sprintf("https://storage.googleapis.com/chrome-for-testing-public/%s/%s/chrome-%s.zip", version, platform, platform)
}

func getSystemFirefoxLocale() string {
	sys := GetHostSystemLocale()
	low := strings.ToLower(sys)
	if strings.HasPrefix(low, "zh") {
		if strings.Contains(low, "tw") {
			return "zh-TW"
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
		return "es-ES"
	}
	if strings.HasPrefix(low, "it") {
		return "it"
	}
	return "en-US"
}

func getFirefoxPlaywrightRevision(version string) string {
	if strings.HasPrefix(version, "156") {
		return "1549" // 对应 Firefox 156.0 官方稳定构建
	}
	if strings.HasPrefix(version, "140") {
		return "1525" // 对应 Firefox 140 ESR 体系构建
	}
	return "1549"
}

func getFirefoxDownloadURL(version string) string {
	rev := getFirefoxPlaywrightRevision(version)
	if runtime.GOOS == "darwin" {
		if runtime.GOARCH == "arm64" {
			return fmt.Sprintf("https://playwright.azureedge.net/builds/firefox/%s/firefox-mac-arm64.zip", rev)
		}
		return fmt.Sprintf("https://playwright.azureedge.net/builds/firefox/%s/firefox-mac.zip", rev)
	}
	return fmt.Sprintf("https://playwright.azureedge.net/builds/firefox/%s/firefox-win64.zip", rev)
}

// isKernelExecutableValid 严格校验内核主程序及必备动态链接库完整性，杜绝空壳、残缺文件
func isKernelExecutableValid(path, kernelType string) bool {
	if path == "" {
		return false
	}
	if kernelType == "safari" && path == "emulated" {
		return true
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if info.Size() < 100*1024 {
		return false
	}

	dir := filepath.Dir(path)

	if runtime.GOOS == "windows" {
		if kernelType == "firefox" {
			hasXul := fileExistsAndNonEmpty(filepath.Join(dir, "xul.dll"))
			hasOmni := fileExistsAndNonEmpty(filepath.Join(dir, "omni.ja")) ||
				fileExistsAndNonEmpty(filepath.Join(dir, "browser", "omni.ja"))
			if !hasXul && !hasOmni {
				return false
			}
		} else if kernelType == "chrome" || kernelType == "safari" {
			hasDll := fileExistsAndNonEmpty(filepath.Join(dir, "chrome.dll"))
			hasPak := fileExistsAndNonEmpty(filepath.Join(dir, "resources.pak")) ||
				fileExistsAndNonEmpty(filepath.Join(dir, "chrome_100_percent.pak"))
			if !hasDll && !hasPak && kernelType != "safari" {
				return false
			}
		}
	}
	return true
}

func fileExistsAndNonEmpty(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() > 0
}

// GetFastOfficialKernels 毫秒级返回官方版本清单
func GetFastOfficialKernels() []KernelVersionInfo {
	cachedOfficialKernelsMu.RLock()
	if len(cachedOfficialKernels) > 0 {
		res := make([]KernelVersionInfo, len(cachedOfficialKernels))
		copy(res, cachedOfficialKernels)
		cachedOfficialKernelsMu.RUnlock()
		return res
	}
	cachedOfficialKernelsMu.RUnlock()

	defaults := []KernelVersionInfo{
		{Type: "chrome", Version: "133.0.6943.98", Milestone: "133", DownloadURL: getChromeCfTDownloadURL("133.0.6943.98")},
		{Type: "chrome", Version: "132.0.6834.160", Milestone: "132", DownloadURL: getChromeCfTDownloadURL("132.0.6834.160")},
		{Type: "firefox", Version: "134.0.2", Milestone: "134", DownloadURL: getFirefoxDownloadURL("134.0.2")},
		{Type: "firefox", Version: "133.0.3", Milestone: "133", DownloadURL: getFirefoxDownloadURL("133.0.3")},
	}

	cachedOfficialKernelsMu.Lock()
	cachedOfficialKernels = defaults
	cachedOfficialKernelsMu.Unlock()

	fetchOfficialOnce.Do(func() {
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			latest, err := FetchRecentKernels(bgCtx, nil)
			if err == nil && len(latest) > 0 {
				cachedOfficialKernelsMu.Lock()
				cachedOfficialKernels = latest
				cachedOfficialKernelsMu.Unlock()
			}
		}()
	})

	return defaults
}

// InvalidateOfficialKernelsCache 清理官方内核内存缓存
func InvalidateOfficialKernelsCache() {
	cachedOfficialKernelsMu.Lock()
	cachedOfficialKernels = nil
	cachedOfficialKernelsMu.Unlock()
}

// DetectLocalBrowsers 智能扫描宿主机已安装的 Chrome 和 Firefox 路径
func DetectLocalBrowsers() []LocalBrowserPath {
	var results []LocalBrowserPath

	if runtime.GOOS == "windows" {
		chromePaths := []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\Application\chrome.exe`),
		}
		for _, p := range chromePaths {
			if _, err := os.Stat(p); err == nil {
				results = append(results, LocalBrowserPath{Type: "chrome", Path: p})
				break
			}
		}

		firefoxPaths := []string{
			`C:\Program Files\Mozilla Firefox\firefox.exe`,
			`C:\Program Files (x86)\Mozilla Firefox\firefox.exe`,
			filepath.Join(os.Getenv("LOCALAPPDATA"), `Mozilla Firefox\firefox.exe`),
		}
		for _, p := range firefoxPaths {
			if _, err := os.Stat(p); err == nil {
				results = append(results, LocalBrowserPath{Type: "firefox", Path: p})
				break
			}
		}
	} else if runtime.GOOS == "darwin" {
		chromePath := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		if _, err := os.Stat(chromePath); err == nil {
			results = append(results, LocalBrowserPath{Type: "chrome", Path: chromePath})
		}
		firefoxPath := "/Applications/Firefox.app/Contents/MacOS/firefox"
		if _, err := os.Stat(firefoxPath); err == nil {
			results = append(results, LocalBrowserPath{Type: "firefox", Path: firefoxPath})
		}
		safariPath := "/Applications/Safari.app/Contents/MacOS/Safari"
		if _, err := os.Stat(safariPath); err == nil {
			results = append(results, LocalBrowserPath{Type: "safari", Path: safariPath})
		} else if _, err := os.Stat("/Applications/Safari.app"); err == nil {
			results = append(results, LocalBrowserPath{Type: "safari", Path: "/Applications/Safari.app"})
		}
	}

	return results
}

// FetchRecentKernels 获取 Chrome 与 Firefox 官方最近两代版本信息
func FetchRecentKernels(ctx context.Context, proxyCfg *ProxyConfig) ([]KernelVersionInfo, error) {
	client, err := BuildHTTPClient(proxyCfg, 8*time.Second)
	if err != nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}

	var list []KernelVersionInfo

	// 1. Chrome for Testing (CfT) 最近两版
	chromeVersions, err := fetchChromeCfTVersions(ctx, client)
	if err == nil && len(chromeVersions) > 0 {
		list = append(list, chromeVersions...)
	} else {
		list = append(list,
			KernelVersionInfo{
				Type:        "chrome",
				Version:     "133.0.6943.98",
				Milestone:   "133",
				DownloadURL: getChromeCfTDownloadURL("133.0.6943.98"),
			},
			KernelVersionInfo{
				Type:        "chrome",
				Version:     "132.0.6834.160",
				Milestone:   "132",
				DownloadURL: getChromeCfTDownloadURL("132.0.6834.160"),
			},
		)
	}

	// 2. Firefox 最近两版
	firefoxVersions, err := fetchFirefoxVersions(ctx, client)
	if err == nil && len(firefoxVersions) > 0 {
		list = append(list, firefoxVersions...)
	} else {
		list = append(list,
			KernelVersionInfo{
				Type:        "firefox",
				Version:     "134.0.2",
				Milestone:   "134",
				DownloadURL: getFirefoxDownloadURL("134.0.2"),
			},
			KernelVersionInfo{
				Type:        "firefox",
				Version:     "133.0.3",
				Milestone:   "133",
				DownloadURL: getFirefoxDownloadURL("133.0.3"),
			},
		)
	}

	return list, nil
}

func fetchChromeCfTVersions(ctx context.Context, client *http.Client) ([]KernelVersionInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CfT API 状态非200: %d", resp.StatusCode)
	}

	var data struct {
		Channels struct {
			Stable struct {
				Version   string `json:"version"`
				Downloads struct {
					Chrome []struct {
						Platform string `json:"platform"`
						URL      string `json:"url"`
					} `json:"chrome"`
				} `json:"downloads"`
			} `json:"Stable"`
			Beta struct {
				Version   string `json:"version"`
				Downloads struct {
					Chrome []struct {
						Platform string `json:"platform"`
						URL      string `json:"url"`
					} `json:"chrome"`
				} `json:"downloads"`
			} `json:"Beta"`
		} `json:"channels"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	platform := getCfTPlatform()
	var res []KernelVersionInfo

	if data.Channels.Stable.Version != "" {
		dl := ""
		for _, item := range data.Channels.Stable.Downloads.Chrome {
			if item.Platform == platform {
				dl = item.URL
				break
			}
		}
		res = append(res, KernelVersionInfo{
			Type:        "chrome",
			Version:     data.Channels.Stable.Version,
			Milestone:   strings.Split(data.Channels.Stable.Version, ".")[0],
			DownloadURL: dl,
		})
	}

	if data.Channels.Beta.Version != "" {
		dl := ""
		for _, item := range data.Channels.Beta.Downloads.Chrome {
			if item.Platform == platform {
				dl = item.URL
				break
			}
		}
		res = append(res, KernelVersionInfo{
			Type:        "chrome",
			Version:     data.Channels.Beta.Version,
			Milestone:   strings.Split(data.Channels.Beta.Version, ".")[0],
			DownloadURL: dl,
		})
	}

	return res, nil
}

func fetchFirefoxVersions(ctx context.Context, client *http.Client) ([]KernelVersionInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://product-details.mozilla.org/1.0/firefox_versions.json", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Mozilla API 状态非200: %d", resp.StatusCode)
	}

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var res []KernelVersionInfo
	if v, ok := data["LATEST_FIREFOX_VERSION"]; ok && v != "" {
		res = append(res, KernelVersionInfo{
			Type:        "firefox",
			Version:     v,
			Milestone:   strings.Split(v, ".")[0],
			DownloadURL: getFirefoxDownloadURL(v),
		})
	}
	if v, ok := data["FIREFOX_ESR"]; ok && v != "" {
		res = append(res, KernelVersionInfo{
			Type:        "firefox",
			Version:     v,
			Milestone:   strings.Split(v, ".")[0],
			DownloadURL: getFirefoxDownloadURL(v),
		})
	}

	return res, nil
}

// DownloadAndExtractKernel 下载并解压内核至目标目录
func DownloadAndExtractKernel(ctx context.Context, dlURL, targetDir string, progressFn func(percent int)) error {
	if dlURL == "" {
		return errors.New("下载链接为空")
	}

	kernelType := "chrome"
	if strings.Contains(strings.ToLower(targetDir), "firefox") || strings.Contains(strings.ToLower(dlURL), "firefox") {
		kernelType = "firefox"
	}

	parentDir := filepath.Dir(targetDir)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("创建内核存储根目录失败: %w", err)
	}

	// 1. 创建隔离的 staging 临时工作区
	stagingDir, err := os.MkdirTemp(parentDir, ".staging_*")
	if err != nil {
		return fmt.Errorf("创建临时解压工作区失败: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	finalURLPath := strings.ToLower(dlURL)
	isExe := strings.HasSuffix(finalURLPath, ".exe") || strings.Contains(finalURLPath, ".exe")
	isDmg := strings.HasSuffix(finalURLPath, ".dmg") || strings.Contains(finalURLPath, ".dmg")

	tmpPackage := filepath.Join(stagingDir, "package.tmp")
	if isExe {
		tmpPackage = filepath.Join(stagingDir, "setup.exe")
	} else if isDmg {
		tmpPackage = filepath.Join(stagingDir, "package.dmg")
	} else {
		tmpPackage = filepath.Join(stagingDir, "package.zip")
	}

	var downloaded int64
	var total int64
	maxRetries := 5
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", dlURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		if downloaded > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", downloaded))
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("网络连接官方源失败: %w", err)
			time.Sleep(1 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			resp.Body.Close()
			if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && total > 0 && downloaded >= total {
				break
			}
			return fmt.Errorf("下载官方内核返回异常状态码: %d", resp.StatusCode)
		}

		if resp.StatusCode == http.StatusOK {
			downloaded = 0
			total = resp.ContentLength
			_ = os.Remove(tmpPackage)
		} else if resp.StatusCode == http.StatusPartialContent {
			if total == 0 && resp.ContentLength > 0 {
				total = downloaded + resp.ContentLength
			}
		}

		openFlag := os.O_CREATE | os.O_WRONLY
		if downloaded > 0 {
			openFlag |= os.O_APPEND
		}
		out, err := os.OpenFile(tmpPackage, openFlag, 0644)
		if err != nil {
			resp.Body.Close()
			return fmt.Errorf("打开临时安装包失败: %w", err)
		}

		buf := make([]byte, 64*1024)
		var readErr error
		for {
			select {
			case <-ctx.Done():
				out.Close()
				resp.Body.Close()
				return ctx.Err()
			default:
			}

			n, rErr := resp.Body.Read(buf)
			if n > 0 {
				if _, wErr := out.Write(buf[:n]); wErr != nil {
					out.Close()
					resp.Body.Close()
					return fmt.Errorf("写入临时安装包失败 (可能磁盘空间不足): %w", wErr)
				}
				downloaded += int64(n)
				if total > 0 && progressFn != nil {
					pct := int(float64(downloaded) / float64(total) * 70)
					if pct < 1 {
						pct = 1
					}
					if pct > 70 {
						pct = 70
					}
					progressFn(pct)
				}
			}
			if rErr != nil {
				readErr = rErr
				break
			}
		}
		out.Close()
		resp.Body.Close()

		if readErr == io.EOF {
			lastErr = nil
			break
		}
		lastErr = fmt.Errorf("网络流中断: %w (已自动保持断点，准备重试)", readErr)
		time.Sleep(1 * time.Second)
	}

	if lastErr != nil {
		return lastErr
	}

	if progressFn != nil {
		progressFn(75)
	}

	// 2. 解压到 staging 内部的 extracted 目录
	extractedDir := filepath.Join(stagingDir, "extracted")
	if err := os.MkdirAll(extractedDir, 0755); err != nil {
		return fmt.Errorf("创建临时解压目标目录失败: %w", err)
	}

	if isExe {
		if runtime.GOOS == "windows" {
			tarCmd := exec.Command("tar.exe", "-xf", tmpPackage, "-C", extractedDir)
			if err := tarCmd.Run(); err != nil {
				return fmt.Errorf("解压安装包失败: %w", err)
			}
			coreDir := filepath.Join(extractedDir, "core")
			if fi, err := os.Stat(coreDir); err == nil && fi.IsDir() {
				entries, _ := os.ReadDir(coreDir)
				for _, entry := range entries {
					oldP := filepath.Join(coreDir, entry.Name())
					newP := filepath.Join(extractedDir, entry.Name())
					_ = os.Rename(oldP, newP)
				}
				_ = os.RemoveAll(coreDir)
			}
			_ = os.Remove(filepath.Join(extractedDir, "setup.exe"))
		} else {
			return fmt.Errorf("当前平台不支持 .exe 格式内核包，请使用 zip/dmg 格式")
		}
		CleanInstallerArtifacts(extractedDir)

	} else if isDmg {
		if runtime.GOOS == "darwin" {
			mountDir := filepath.Join(stagingDir, "dmg_mount")
			_ = os.MkdirAll(mountDir, 0755)
			cmd := exec.Command("hdiutil", "attach", tmpPackage, "-mountpoint", mountDir, "-nobrowse", "-quiet")
			if err := cmd.Run(); err == nil {
				entries, _ := os.ReadDir(mountDir)
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".app") {
						srcApp := filepath.Join(mountDir, entry.Name())
						dstApp := filepath.Join(extractedDir, entry.Name())
						_ = exec.Command("cp", "-R", srcApp, dstApp).Run()
						break
					}
				}
				_ = exec.Command("hdiutil", "detach", mountDir, "-quiet").Run()
			}
		}
	} else {
		if err := unzipArchive(tmpPackage, extractedDir); err != nil {
			return fmt.Errorf("解压 zip 压缩包失败: %w", err)
		}
	}

	if progressFn != nil {
		progressFn(90)
	}

	// 3. 严格完整性自检
	validPath := LocateDownloadedKernel(extractedDir, kernelType)
	if validPath == "" || !isKernelExecutableValid(validPath, kernelType) {
		return fmt.Errorf("内核完整性校验未通过: 缺失核心组件或文件损坏")
	}

	if progressFn != nil {
		progressFn(95)
	}

	// 4. 清理旧目录并原子替换
	_ = CleanKernelDir(targetDir)

	if err := os.Rename(extractedDir, targetDir); err != nil {
		if cErr := copyDir(extractedDir, targetDir); cErr != nil {
			return fmt.Errorf("部署内核至目标目录失败: %w", cErr)
		}
	}

	// 5. 目标目录最终验收
	finalPath := LocateDownloadedKernel(targetDir, kernelType)
	if finalPath == "" || !isKernelExecutableValid(finalPath, kernelType) {
		_ = CleanKernelDir(targetDir)
		return fmt.Errorf("内核部署验证失败，已自动回滚清理")
	}

	if runtime.GOOS == "darwin" {
		_ = os.Chmod(finalPath, 0755)
		_ = exec.Command("xattr", "-dr", "com.apple.quarantine", targetDir).Run()
	}

	CleanInstallerArtifacts(targetDir)
	if kernelType == "firefox" {
		SanitizeFirefoxKernel(targetDir)
	}

	if progressFn != nil {
		progressFn(100)
	}
	return nil
}
