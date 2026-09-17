package public

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ProviderURL struct {
	Label  string `json:"lb"`
	URL    string `json:"url"`
	Format string `json:"fmt"`
}

type BuiltinProvider struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	KeyPfx   string                 `json:"kp"`
	URLs     map[string]ProviderURL `json:"urls"`
	Tools    map[string]string      `json:"tools"` // "cl": "direct", "cx": "shim"
	BaseURL  string                 `json:"baseUrl"`
	URLTag   string                 `json:"urlTag"`
	APIKey   string                 `json:"apiKey"`
	Model    string                 `json:"model"`
	CustUrl  string                 `json:"custUrl"`
	CustName string                 `json:"custName"`
	IsCustom bool                   `json:"isC"`
	Done     bool                   `json:"done"`
}

type ProviderStore struct {
	mu   sync.Mutex
	path string
}

func getProviderStorePath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".ai-runtime-manager")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "providers.json")
}

func loadSavedProviders() map[string]map[string]interface{} {
	p := getProviderStorePath()
	data, err := os.ReadFile(p)
	if err != nil {
		return make(map[string]map[string]interface{})
	}
	var res map[string]map[string]interface{}
	_ = json.Unmarshal(data, &res)
	if res == nil {
		res = make(map[string]map[string]interface{})
	}
	return res
}

func saveSavedProviders(m map[string]map[string]interface{}) error {
	p := getProviderStorePath()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

var builtinCatalog = []struct {
	ID     string
	Name   string
	KeyPfx string
	URLs   []ProviderURL
	Tools  map[string]string
}{
	{
		ID: "deepseek", Name: "DeepSeek", KeyPfx: "sk-",
		URLs: []ProviderURL{
			{Label: "标准", URL: "https://api.deepseek.com", Format: "openai"},
			{Label: "Claude兼容", URL: "https://api.deepseek.com/anthropic", Format: "claude"},
		},
		Tools: map[string]string{"cl": "direct", "cx": "direct"},
	},
	{
		ID: "openai", Name: "OpenAI", KeyPfx: "sk-",
		URLs:  []ProviderURL{{Label: "标准", URL: "https://api.openai.com/v1", Format: "openai"}},
		Tools: map[string]string{"cl": "direct", "cx": "direct"},
	},
	{
		ID: "anthropic", Name: "Anthropic Claude", KeyPfx: "sk-ant-",
		URLs:  []ProviderURL{{Label: "标准", URL: "https://api.anthropic.com/v1", Format: "claude"}},
		Tools: map[string]string{"cl": "direct", "cx": "direct"},
	},
	{
		ID: "gemini", Name: "Google Gemini", KeyPfx: "AIza",
		URLs:  []ProviderURL{{Label: "标准", URL: "https://generativelanguage.googleapis.com/v1beta", Format: "gemini"}},
		Tools: map[string]string{"cl": "direct", "cx": "direct"},
	},
	{
		ID: "groq", Name: "Groq", KeyPfx: "gsk_",
		URLs:  []ProviderURL{{Label: "标准", URL: "https://api.groq.com/openai/v1", Format: "openai"}},
		Tools: map[string]string{"cl": "direct", "cx": "direct"},
	},
	{
		ID: "qwen", Name: "通义千问 Qwen", KeyPfx: "sk-",
		URLs:  []ProviderURL{{Label: "标准", URL: "https://dashscope.aliyuncs.com/compatible-mode/v1", Format: "openai"}},
		Tools: map[string]string{"cl": "direct", "cx": "direct"},
	},
	{
		ID: "silicon", Name: "硅基流动 SiliconFlow", KeyPfx: "sk-",
		URLs:  []ProviderURL{{Label: "标准", URL: "https://api.siliconflow.cn/v1", Format: "openai"}},
		Tools: map[string]string{"cl": "direct", "cx": "direct"},
	},
}

func ListProviders() []map[string]interface{} {
	saved := loadSavedProviders()
	var list []map[string]interface{}

	for _, bp := range builtinCatalog {
		s := saved[bp.ID]
		apiKey := ""
		model := ""
		baseUrl := bp.URLs[0].URL
		urlTag := bp.URLs[0].Label
		done := false

		if s != nil {
			if v, ok := s["apiKey"].(string); ok {
				apiKey = v
				done = apiKey != ""
			}
			if v, ok := s["model"].(string); ok {
				model = v
			}
			if v, ok := s["baseUrl"].(string); ok && v != "" {
				baseUrl = v
			}
			if v, ok := s["urlTag"].(string); ok && v != "" {
				urlTag = v
			}
		}

		urlsList := make([]map[string]string, len(bp.URLs))
		for i, u := range bp.URLs {
			urlsList[i] = map[string]string{"lb": u.Label, "url": u.URL, "fmt": u.Format}
		}

		list = append(list, map[string]interface{}{
			"id":       bp.ID,
			"name":     bp.Name,
			"kp":       bp.KeyPfx,
			"urls":     urlsList,
			"urlTag":   urlTag,
			"baseUrl":  baseUrl,
			"fmt":      bp.URLs[0].Format,
			"tools":    bp.Tools,
			"isC":      false,
			"done":     done,
			"apiKey":   apiKey,
			"model":    model,
			"custUrl":  baseUrl,
		})
	}

	return list
}

func SaveProvider(id, apiKey, model, baseUrl, urlTag string) error {
	saved := loadSavedProviders()
	if saved[id] == nil {
		saved[id] = make(map[string]interface{})
	}
	if apiKey != "" {
		saved[id]["apiKey"] = apiKey
	}
	if model != "" {
		saved[id]["model"] = model
	}
	if baseUrl != "" {
		saved[id]["baseUrl"] = baseUrl
	}
	if urlTag != "" {
		saved[id]["urlTag"] = urlTag
	}
	saved[id]["savedAt"] = time.Now().UnixMilli()
	return saveSavedProviders(saved)
}

func DeleteProvider(id string) error {
	saved := loadSavedProviders()
	delete(saved, id)
	return saveSavedProviders(saved)
}

func TestProviderAPI(id, baseUrl, fmtType string) map[string]interface{} {
	saved := loadSavedProviders()
	cfg := saved[id]
	if cfg == nil || cfg["apiKey"] == nil {
		return map[string]interface{}{
			"success": false,
			"error":   "未配置 API Key",
		}
	}
	apiKey := cfg["apiKey"].(string)
	if baseUrl == "" {
		if u, ok := cfg["baseUrl"].(string); ok {
			baseUrl = u
		}
	}
	baseUrl = strings.TrimRight(baseUrl, "/")

	reqURL := baseUrl + "/models"
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return map[string]interface{}{"success": false, "error": err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"latency": lat,
			"error":   err.Error(),
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var models []string
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(body, &jsonMap); err == nil {
		if dataList, ok := jsonMap["data"].([]interface{}); ok {
			for _, item := range dataList {
				if m, ok := item.(map[string]interface{}); ok {
					if idStr, ok := m["id"].(string); ok {
						models = append(models, idStr)
					}
				}
			}
		}
	}

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	return map[string]interface{}{
		"success":  ok,
		"latency":  lat,
		"status":   resp.StatusCode,
		"models":   models,
		"noModels": len(models) == 0,
	}
}

func ApplyProvider(id string, tools []string) map[string]interface{} {
	saved := loadSavedProviders()
	cfg := saved[id]
	if cfg == nil || cfg["apiKey"] == nil {
		return map[string]interface{}{"success": false, "error": "Provider not configured"}
	}
	apiKey := cfg["apiKey"].(string)
	model, _ := cfg["model"].(string)
	baseUrl, _ := cfg["baseUrl"].(string)

	home, _ := os.UserHomeDir()
	claudePath := filepath.Join(home, ".claude", "settings.json")
	_ = os.MkdirAll(filepath.Dir(claudePath), 0o755)

	var results []map[string]interface{}
	claudeMap := make(map[string]interface{})
	if raw, err := os.ReadFile(claudePath); err == nil {
		_ = json.Unmarshal(raw, &claudeMap)
	}
	claudeMap["apiKey"] = apiKey
	if baseUrl != "" {
		claudeMap["baseURL"] = baseUrl
	}
	if model != "" {
		claudeMap["model"] = model
	}
	data, _ := json.MarshalIndent(claudeMap, "", "  ")
	_ = os.WriteFile(claudePath, data, 0o644)

	results = append(results, map[string]interface{}{
		"tool":   "cl",
		"name":   "Claude CLI",
		"action": "ok",
	})

	return map[string]interface{}{
		"success": true,
		"results": results,
	}
}
