package public

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type ToolItem struct {
	Command  string   `json:"command"`
	Args     []string `json:"args"`
	Cwd      string   `json:"cwd"`
	Type     string   `json:"type"`
	ProxyEnv []string `json:"proxyEnv"`
}

type AppConfig struct {
	Lang            string              `json:"lang"`
	AutoDetectProxy bool                `json:"autoDetectProxy"`
	ProxyTimeout    int                 `json:"proxyTimeout"`
	Tools           map[string]ToolItem `json:"tools"`
}

var (
	cfgMu      sync.RWMutex
	currentCfg *AppConfig
	configPath string
)

func defaultConfig() *AppConfig {
	return &AppConfig{
		Lang:            "zh-CN",
		AutoDetectProxy: true,
		ProxyTimeout:    5000,
		Tools: map[string]ToolItem{
			"claude": {
				Command:  "claude",
				Args:     []string{},
				Cwd:      "",
				Type:     "cli",
				ProxyEnv: []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"},
			},
			"codex": {
				Command:  "codex",
				Args:     []string{},
				Cwd:      "",
				Type:     "cli",
				ProxyEnv: []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"},
			},
		},
	}
}

// InitConfig initializes the shared configuration file at the given directory.
func InitConfig(dir string) {
	cfgMu.Lock()
	defer cfgMu.Unlock()

	_ = os.MkdirAll(dir, 0o755)
	configPath = filepath.Join(dir, "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		currentCfg = defaultConfig()
		saveConfigLocked()
		return
	}

	var loaded AppConfig
	if err := json.Unmarshal(data, &loaded); err != nil {
		currentCfg = defaultConfig()
	} else {
		currentCfg = &loaded
		if currentCfg.Tools == nil {
			currentCfg.Tools = defaultConfig().Tools
		}
	}
}

func GetConfig() *AppConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if currentCfg == nil {
		return defaultConfig()
	}
	return currentCfg
}

func UpdateLang(lang string) {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if currentCfg != nil {
		currentCfg.Lang = lang
		saveConfigLocked()
	}
}

func UpdateToolCwd(tool, cwd string) {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if currentCfg != nil && currentCfg.Tools != nil {
		t, ok := currentCfg.Tools[tool]
		if !ok {
			t = ToolItem{Command: tool, Args: []string{}, Type: "cli"}
		}
		t.Cwd = cwd
		currentCfg.Tools[tool] = t
		saveConfigLocked()
	}
}

func GetToolCwdMap() map[string]string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	res := make(map[string]string)
	if currentCfg != nil && currentCfg.Tools != nil {
		for k, v := range currentCfg.Tools {
			res[k] = v.Cwd
		}
	}
	return res
}

func saveConfigLocked() {
	if configPath == "" || currentCfg == nil {
		return
	}
	data, err := json.MarshalIndent(currentCfg, "", "  ")
	if err == nil {
		_ = os.WriteFile(configPath, data, 0o644)
	}
}
