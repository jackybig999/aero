// Package tokenstore 多用户 token 持久化（data-dir/tokens.json）。
// 契约：字段只增不改；热重载用 Reload。
package tokenstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
)

// Record 一条 token 记录（v1 冻结字段）
type Record struct {
	Token     string    `json:"token"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type fileDoc struct {
	Version int      `json:"version"` // schema 版本，当前 1
	Tokens  []Record `json:"tokens"`
}

// Store 文件 + 内存 Validator 同步
type Store struct {
	mu   sync.Mutex
	path string
	v    *auth.Validator
}

// Open 加载或创建 store，并灌入 validator。
func Open(dir string, v *auth.Validator) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "tokens.json"), v: v}
	if err := s.loadInto(false); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload 从磁盘重载（SIGHUP / Admin）；替换内存 token 表。
func (s *Store) Reload() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Clear()
	if err := s.loadIntoLocked(true); err != nil {
		return 0, err
	}
	return s.v.Count(), nil
}

func (s *Store) loadInto(clearFirst bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if clearFirst {
		s.v.Clear()
	}
	return s.loadIntoLocked(false)
}

func (s *Store) loadIntoLocked(alreadyCleared bool) error {
	_ = alreadyCleared
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc fileDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	now := time.Now()
	for _, r := range doc.Tokens {
		if r.Token == "" {
			continue
		}
		if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
			continue
		}
		ttl := time.Until(r.ExpiresAt)
		if r.ExpiresAt.IsZero() || ttl <= 0 {
			ttl = 365 * 24 * time.Hour
		}
		s.v.AddToken(r.Token, r.Label, ttl)
	}
	return nil
}

func (s *Store) saveLocked() error {
	list := s.v.ListTokens()
	doc := fileDoc{Version: 1, Tokens: make([]Record, 0, len(list))}
	for _, t := range list {
		doc.Tokens = append(doc.Tokens, Record{
			Token: t.Token, Label: t.Label, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Ensure 确保 token 存在并落盘。
func (s *Store) Ensure(token, label string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.v.Validate(token) {
		s.v.AddToken(token, label, ttl)
	}
	return s.saveLocked()
}

// Add 新增 token 并持久化。
func (s *Store) Add(token, label string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token == "" {
		token = auth.GenerateToken()
	}
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}
	if label == "" {
		label = "user"
	}
	s.v.AddToken(token, label, ttl)
	return s.saveLocked()
}

// AddReturn 新增并返回 token。
func (s *Store) AddReturn(token, label string, ttl time.Duration) (string, error) {
	if token == "" {
		token = auth.GenerateToken()
	}
	if err := s.Add(token, label, ttl); err != nil {
		return "", err
	}
	return token, nil
}

// Remove 吊销并落盘。
func (s *Store) Remove(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.RemoveToken(token)
	return s.saveLocked()
}

// List 当前 token。
func (s *Store) List() []Record {
	list := s.v.ListTokens()
	out := make([]Record, 0, len(list))
	for _, t := range list {
		out = append(out, Record{
			Token: t.Token, Label: t.Label, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		})
	}
	return out
}

// Path 文件路径。
func (s *Store) Path() string { return s.path }
