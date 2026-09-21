package apimatrix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type APIProviderConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	BaseURL     string `json:"base_url"`
	DefaultURL  string `json:"default_url"`
	APIKey      string `json:"api_key"`
	Status      string `json:"status"` // "untested", "valid", "invalid", "error"
	LatencyMS   int64  `json:"latency_ms"`
	LastChecked string `json:"last_checked"`
	Model       string `json:"model"`
}

type APIVault struct {
	filePath  string
	providers map[string]*APIProviderConfig
	mu        sync.RWMutex
}

func NewAPIVault(dataDir string) *APIVault {
	fp := filepath.Join(dataDir, "apimatrix.json")
	v := &APIVault{
		filePath:  fp,
		providers: make(map[string]*APIProviderConfig),
	}
	v.initDefaults()
	v.load()
	return v
}

func (v *APIVault) initDefaults() {
	defaults := []APIProviderConfig{
		{ID: "openai", Name: "OpenAI", DefaultURL: "https://api.openai.com/v1", Model: "gpt-4o"},
		{ID: "anthropic", Name: "Anthropic Claude", DefaultURL: "https://api.anthropic.com/v1", Model: "claude-3-7-sonnet"},
		{ID: "gemini", Name: "Google Gemini", DefaultURL: "https://generativelanguage.googleapis.com/v1beta", Model: "gemini-2.5-pro"},
		{ID: "deepseek", Name: "DeepSeek", DefaultURL: "https://api.deepseek.com/v1", Model: "deepseek-chat"},
		{ID: "openrouter", Name: "OpenRouter", DefaultURL: "https://openrouter.ai/api/v1", Model: "auto"},
		{ID: "groq", Name: "Groq", DefaultURL: "https://api.groq.com/openai/v1", Model: "llama-3.3-70b-versatile"},
	}

	for _, d := range defaults {
		cfg := d
		cfg.BaseURL = cfg.DefaultURL
		cfg.Status = "untested"
		v.providers[cfg.ID] = &cfg
	}
}

func (v *APIVault) GetAll() []*APIProviderConfig {
	v.mu.RLock()
	defer v.mu.RUnlock()

	res := make([]*APIProviderConfig, 0, len(v.providers))
	order := []string{"openai", "anthropic", "gemini", "deepseek", "openrouter", "groq"}
	for _, id := range order {
		if p, ok := v.providers[id]; ok {
			res = append(res, p)
		}
	}
	return res
}

func (v *APIVault) SaveKey(id, key, baseURL string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if p, ok := v.providers[id]; ok {
		p.APIKey = key
		if baseURL != "" {
			p.BaseURL = baseURL
		}
		v.save()
	}
}

func (v *APIVault) UpdateStatus(id, status string, latency int64, checkedAt string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if p, ok := v.providers[id]; ok {
		p.Status = status
		p.LatencyMS = latency
		p.LastChecked = checkedAt
		v.save()
	}
}

func (v *APIVault) load() {
	b, err := os.ReadFile(v.filePath)
	if err == nil {
		var list []*APIProviderConfig
		if err := json.Unmarshal(b, &list); err == nil {
			for _, it := range list {
				if existing, ok := v.providers[it.ID]; ok {
					if it.APIKey != "" {
						existing.APIKey = it.APIKey
					}
					if it.BaseURL != "" {
						existing.BaseURL = it.BaseURL
					}
					existing.Status = it.Status
					existing.LatencyMS = it.LatencyMS
					existing.LastChecked = it.LastChecked
				}
			}
		}
	}
}

func (v *APIVault) save() {
	list := make([]*APIProviderConfig, 0, len(v.providers))
	for _, p := range v.providers {
		list = append(list, p)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(v.filePath), 0755)
		_ = os.WriteFile(v.filePath, b, 0644)
	}
}
