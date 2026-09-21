package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"aisys/connect/os/internal/domain/proxy"
)

var (
	cachedOfficialKernels   []KernelVersionInfo
	cachedOfficialKernelsMu sync.RWMutex
	fetchOfficialOnce       sync.Once
)

// GetFastOfficialKernels 毫秒级返回官方版本清单 (有缓存读缓存，无缓存使用内置基准并异步静默拉取，杜绝阻塞主线程)
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

// InvalidateOfficialKernelsCache 清理官方内核内存缓存，允许用户主动强制重新扫描检测
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
func FetchRecentKernels(ctx context.Context, proxyCfg *proxy.ProxyConfig) ([]KernelVersionInfo, error) {
	client, err := proxy.BuildHTTPClient(proxyCfg, 8*time.Second)
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
