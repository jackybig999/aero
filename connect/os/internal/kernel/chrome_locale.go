package kernel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/infra/config"
)

// configureChromeUserDataLocale 配置 Chrome 本地化与语言首选项，动态无缝与系统语言同步
func configureChromeUserDataLocale(userDataDir string, fpCfg *fingerprint.FingerprintConfig) (string, string) {
	rawLang := ""
	if fpCfg != nil && len(fpCfg.Languages) > 0 {
		rawLang = strings.TrimSpace(fpCfg.Languages[0])
	}
	if rawLang == "" || strings.EqualFold(rawLang, "system") {
		rawLang = config.GetHostSystemLocale()
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
		appLocale = config.NormalizeLocale(rawLang)
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
	prefPath := filepath.Join(defaultDir, "Preferences")
	var prefs map[string]interface{}
	if data, err := os.ReadFile(prefPath); err == nil {
		_ = json.Unmarshal(data, &prefs)
	}
	if prefs == nil {
		prefs = make(map[string]interface{})
	}
	pIntl, _ := prefs["intl"].(map[string]interface{})
	if pIntl == nil {
		pIntl = make(map[string]interface{})
	}
	pIntl["app_locale"] = appLocale
	pIntl["accept_languages"] = acceptLangs
	pIntl["selected_languages"] = acceptLangs
	prefs["intl"] = pIntl

	// 配置会话自动恢复 (1 = 自动恢复上次打开的所有标签页与会话)
	sessionMap, _ := prefs["session"].(map[string]interface{})
	if sessionMap == nil {
		sessionMap = make(map[string]interface{})
	}
	sessionMap["restore_on_startup"] = 1
	prefs["session"] = sessionMap

	// 确保 Cookie 与站点状态永久保存，标记正常退出
	profileMap, _ := prefs["profile"].(map[string]interface{})
	if profileMap == nil {
		profileMap = make(map[string]interface{})
	}
	profileMap["exit_type"] = "Normal"
	profileMap["exited_cleanly"] = true
	contentSettings, _ := profileMap["default_content_setting_values"].(map[string]interface{})
	if contentSettings == nil {
		contentSettings = make(map[string]interface{})
	}
	contentSettings["cookies"] = 1
	profileMap["default_content_setting_values"] = contentSettings
	prefs["profile"] = profileMap

	if b, err := json.MarshalIndent(prefs, "", "  "); err == nil {
		_ = os.WriteFile(prefPath, b, 0644)
	}

	return appLocale, acceptLangs
}
