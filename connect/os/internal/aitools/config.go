package aitools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type ToolInfo struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Icon       string `json:"icon"`
	Installed  bool   `json:"installed"`
	Path       string `json:"path"`
	Version    string `json:"version,omitempty"`
	CWD        string `json:"cwd"`
	Type       string `json:"type"` // "desktop" | "cli"
	DefaultCmd string `json:"default_cmd"`
}

type ToolStore struct {
	filePath string
	cwds     map[string]string
	mu       sync.RWMutex
}

func NewToolStore(dataDir string) *ToolStore {
	fp := filepath.Join(dataDir, "aitools.json")
	s := &ToolStore{
		filePath: fp,
		cwds:     make(map[string]string),
	}
	s.load()
	return s
}

func (s *ToolStore) SetCWD(key, cwd string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cwds[key] = cwd
	s.save()
}

func (s *ToolStore) GetCWD(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cwds[key]; ok && c != "" {
		return c
	}
	home, err := os.UserHomeDir()
	if err == nil {
		return home
	}
	cwd, _ := os.Getwd()
	return cwd
}

func (s *ToolStore) load() {
	b, err := os.ReadFile(s.filePath)
	if err == nil {
		_ = json.Unmarshal(b, &s.cwds)
	}
}

func (s *ToolStore) save() {
	b, err := json.MarshalIndent(s.cwds, "", "  ")
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(s.filePath), 0755)
		_ = os.WriteFile(s.filePath, b, 0644)
	}
}
