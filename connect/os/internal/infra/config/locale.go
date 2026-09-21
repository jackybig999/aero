package config

import (
	"os/exec"
	"strings"
)

// NormalizeLocale 标准化国家/地区语言标记 (默认国际标准 en-US，绝不硬编码固定中文)
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

// getDarwinLocale 通过 macOS defaults 命令读取系统语言设置
func getDarwinLocale() string {
	out, err := exec.Command("defaults", "read", "-g", "AppleLocale").Output()
	if err == nil {
		loc := strings.TrimSpace(string(out))
		if loc != "" {
			return loc
		}
	}
	outLang, errLang := exec.Command("defaults", "read", "-g", "AppleLanguages").Output()
	if errLang == nil {
		str := string(outLang)
		if idx := strings.Index(str, "\""); idx != -1 {
			if endIdx := strings.Index(str[idx+1:], "\""); endIdx != -1 {
				lang := str[idx+1 : idx+1+endIdx]
				if lang != "" {
					return lang
				}
			}
		}
	}
	return ""
}

// GetDefaultFingerprintCheckURL 根据语言返回与系统语言完美同步的指纹环境检测页面
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
