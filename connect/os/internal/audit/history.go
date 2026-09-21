package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type HistoryItem struct {
	ID        string `json:"id"`
	Type      string `json:"type"` // "browser", "aitool", "net"
	Name      string `json:"name"`
	Detail    string `json:"detail"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

type HistoryStore struct {
	filePath string
	items    []HistoryItem
	mu       sync.RWMutex
}

func NewHistoryStore(dataDir string) *HistoryStore {
	fp := filepath.Join(dataDir, "history.json")
	s := &HistoryStore{
		filePath: fp,
		items:    make([]HistoryItem, 0),
	}
	s.load()
	return s
}

func (s *HistoryStore) Record(itemType, name, detail, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item := HistoryItem{
		ID:        time.Now().Format("20060102150405.000"),
		Type:      itemType,
		Name:      name,
		Detail:    detail,
		Status:    status,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}

	s.items = append([]HistoryItem{item}, s.items...)
	if len(s.items) > 200 {
		s.items = s.items[:200]
	}
	s.save()
}

func (s *HistoryStore) GetItems() []HistoryItem {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]HistoryItem, len(s.items))
	copy(res, s.items)
	return res
}

func (s *HistoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = s.items[:0]
	s.save()
}

func (s *HistoryStore) load() {
	b, err := os.ReadFile(s.filePath)
	if err == nil {
		_ = json.Unmarshal(b, &s.items)
	}
}

func (s *HistoryStore) save() {
	b, err := json.MarshalIndent(s.items, "", "  ")
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(s.filePath), 0755)
		_ = os.WriteFile(s.filePath, b, 0644)
	}
}
