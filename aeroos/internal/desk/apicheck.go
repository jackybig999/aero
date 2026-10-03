package desk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
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

func (v *APIVault) getAllLocked() []*APIProviderConfig {
	res := make([]*APIProviderConfig, 0, len(v.providers))
	order := []string{"openai", "anthropic", "gemini", "deepseek", "openrouter", "groq"}
	for _, id := range order {
		if p, ok := v.providers[id]; ok {
			res = append(res, p)
		}
	}
	return res
}

func (v *APIVault) GetAll() []*APIProviderConfig {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.getAllLocked()
}

func (v *APIVault) SaveKey(id, key, baseURL string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if p, ok := v.providers[id]; ok {
		p.APIKey = key
		if baseURL != "" {
			p.BaseURL = baseURL
		}
		v.saveLocked()
	}
}

func (v *APIVault) UpdateStatus(id, status string, latency int64, checkedAt string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if p, ok := v.providers[id]; ok {
		p.Status = status
		p.LatencyMS = latency
		p.LastChecked = checkedAt
		v.saveLocked()
	}
}

func (v *APIVault) load() {
	b, err := os.ReadFile(v.filePath)
	if err == nil {
		var list []*APIProviderConfig
		if err := json.Unmarshal(b, &list); err == nil {
			for _, item := range list {
				if item.ID != "" {
					if existing, ok := v.providers[item.ID]; ok {
						existing.APIKey = item.APIKey
						if item.BaseURL != "" {
							existing.BaseURL = item.BaseURL
						}
						existing.Status = item.Status
						existing.LatencyMS = item.LatencyMS
						existing.LastChecked = item.LastChecked
					} else {
						v.providers[item.ID] = item
					}
				}
			}
		}
	}
}

func (v *APIVault) saveLocked() {
	list := v.getAllLocked()
	b, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(v.filePath), 0755)
		_ = os.WriteFile(v.filePath, b, 0644)
	}
}

type Tester struct {
	vault     *APIVault
	proxyAddr string
}

func NewTester(vault *APIVault, proxyAddr string) *Tester {
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:55555"
	}
	return &Tester{
		vault:     vault,
		proxyAddr: proxyAddr,
	}
}

func (t *Tester) TestProvider(id string) (string, int64, error) {
	all := t.vault.GetAll()
	var target *APIProviderConfig
	for _, p := range all {
		if p.ID == id {
			target = p
			break
		}
	}

	if target == nil {
		return "error", 0, fmt.Errorf("unknown provider: %s", id)
	}

	if target.APIKey == "" {
		t.vault.UpdateStatus(id, "untested", 0, time.Now().Format("15:04:05"))
		return "untested", 0, fmt.Errorf("未配置 API Key")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}

	if t.proxyAddr != "" {
		if proxyURL, err := url.Parse("http://" + t.proxyAddr); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
	}

	start := time.Now()
	testURL := target.BaseURL
	if testURL == "" {
		testURL = target.DefaultURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return "error", 0, err
	}

	req.Header.Set("User-Agent", "AERO-OS-KeyMatrix/2.0")
	if id == "anthropic" {
		req.Header.Set("x-api-key", target.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	} else if id == "gemini" {
		// query params or key
	} else {
		req.Header.Set("Authorization", "Bearer "+target.APIKey)
	}

	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()

	status := "valid"
	if err != nil {
		status = "error"
		GlobalLogger.Log("WARN", "APIMATRIX", fmt.Sprintf("[%s] 连通性测试异常 (%dms): %v", target.Name, latency, err))
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			status = "invalid"
		} else {
			status = "valid"
		}
		GlobalLogger.Log("INFO", "APIMATRIX", fmt.Sprintf("[%s] 连通性检测完成: status=%s, code=%d, 时延=%dms", target.Name, status, resp.StatusCode, latency))
	}

	nowStr := time.Now().Format("15:04:05")
	t.vault.UpdateStatus(id, status, latency, nowStr)
	return status, latency, err
}
