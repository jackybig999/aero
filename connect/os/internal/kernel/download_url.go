package kernel

import (
	"fmt"
	"runtime"
	"strings"

	"aisys/connect/os/internal/infra/config"
)

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
	sys := config.GetHostSystemLocale()
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
	// Windows: 微软 Playwright 官方纯便携 zip 归档，免安装、零服务、纯解压即用
	return fmt.Sprintf("https://playwright.azureedge.net/builds/firefox/%s/firefox-win64.zip", rev)
}
