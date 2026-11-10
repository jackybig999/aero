// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ==========================================
// 1. Token Validator & Nonce Anti-Replay
// ==========================================

// TokenInfo holds in-memory metadata for a token
type TokenInfo struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Label     string    `json:"label"`
}

// Validator 保存有效 token 及其到期时间。防重放由 TLS 提供；不再维护 nonce 表
// （C3 §5，审查 P0-8：全局 nonce 表可被单个用户耗尽）。
type Validator struct {
	mu     sync.RWMutex
	tokens map[string]*TokenInfo
}

// NewValidator 创建空的 Validator。
func NewValidator() *Validator {
	return &Validator{tokens: make(map[string]*TokenInfo)}
}

// AddToken registers a token in memory
func (v *Validator) AddToken(token string, label string, ttl time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	v.tokens[token] = &TokenInfo{
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Label:     label,
	}
}

// Validate checks whether token exists and has not expired
func (v *Validator) Validate(token string) bool {
	v.mu.RLock()
	info, ok := v.tokens[token]
	v.mu.RUnlock()

	if !ok {
		return false
	}

	match := subtle.ConstantTimeCompare([]byte(token), []byte(info.Token)) == 1
	valid := time.Now().Before(info.ExpiresAt)
	return match && valid
}

// RemoveToken removes token from in-memory validator
func (v *Validator) RemoveToken(token string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.tokens, token)
}

// replaceTokens 原子替换全部 token（Reload 使用）。
func (v *Validator) replaceTokens(tokens map[string]*TokenInfo) {
	v.mu.Lock()
	v.tokens = tokens
	v.mu.Unlock()
}

// mergeTokens 把 tokens 并入现有集合，同名覆盖。
func (v *Validator) mergeTokens(tokens map[string]*TokenInfo) {
	v.mu.Lock()
	for k, info := range tokens {
		v.tokens[k] = info
	}
	v.mu.Unlock()
}

// Count returns number of active tokens
func (v *Validator) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.tokens)
}

// ListTokens returns snapshot of in-memory tokens
func (v *Validator) ListTokens() []TokenInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()

	list := make([]TokenInfo, 0, len(v.tokens))
	for _, info := range v.tokens {
		list = append(list, *info)
	}
	return list
}

// GenerateToken generates random 32-byte (256-bit entropy) hex token prefixed with aero_
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read crypto random bytes: %w", err)
	}
	return fmt.Sprintf("aero_%x", b), nil
}

// ==========================================
// 2. Token Persistence Store (tokens.json)
// ==========================================

// TokenRecord represents a persisted token entry
type TokenRecord struct {
	Token     string    `json:"token"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type tokenFileDoc struct {
	Version int           `json:"version"` // schema version = 1
	Tokens  []TokenRecord `json:"tokens"`
}

// TokenStore manages tokens.json disk persistence and syncs with Validator
type TokenStore struct {
	mu   sync.Mutex
	path string
	v    *Validator
}

// OpenTokenStore initializes or loads token store from data directory
func OpenTokenStore(dir string, v *Validator) (*TokenStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &TokenStore{
		path: filepath.Join(dir, "tokens.json"),
		v:    v,
	}
	if err := s.loadInto(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload 从磁盘重载 token：完整解析成功后原子替换 Validator 中的集合。
// 解析失败时返回错误并保留原有 token；替换过程中不存在“全部失效”的窗口。
func (s *TokenStore) Reload() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens, err := s.readTokenFileLocked()
	if err != nil {
		return 0, err
	}
	s.v.replaceTokens(tokens)
	return s.v.Count(), nil
}

// loadInto 启动时把磁盘上的 token 并入 Validator（不清除已有 token）。
func (s *TokenStore) loadInto() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens, err := s.readTokenFileLocked()
	if err != nil {
		return err
	}
	s.v.mergeTokens(tokens)
	return nil
}

// readTokenFileLocked 解析 tokens.json 为新的集合；文件不存在时返回空集合。
// 已过期的 token 跳过；未设置过期时间的 token 视为一年有效（与旧行为一致）。
func (s *TokenStore) readTokenFileLocked() (map[string]*TokenInfo, error) {
	tokens := make(map[string]*TokenInfo)
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return tokens, nil
		}
		return nil, err
	}
	var doc tokenFileDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	now := time.Now()
	for _, r := range doc.Tokens {
		if r.Token == "" {
			continue
		}
		expires := r.ExpiresAt
		if expires.IsZero() {
			expires = now.Add(365 * 24 * time.Hour)
		} else if !now.Before(expires) {
			continue
		}
		created := r.CreatedAt
		if created.IsZero() {
			created = now
		}
		tokens[r.Token] = &TokenInfo{Token: r.Token, CreatedAt: created, ExpiresAt: expires, Label: r.Label}
	}
	return tokens, nil
}

func (s *TokenStore) saveLocked() error {
	list := s.v.ListTokens()
	doc := tokenFileDoc{
		Version: 1,
		Tokens:  make([]TokenRecord, 0, len(list)),
	}
	for _, t := range list {
		doc.Tokens = append(doc.Tokens, TokenRecord{
			Token:     t.Token,
			Label:     t.Label,
			CreatedAt: t.CreatedAt,
			ExpiresAt: t.ExpiresAt,
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

// Ensure makes sure a token exists and persists it to disk
func (s *TokenStore) Ensure(token, label string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.v.Validate(token) {
		s.v.AddToken(token, label, ttl)
	}
	return s.saveLocked()
}

// Add adds a new token and persists it to disk
func (s *TokenStore) Add(token, label string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token == "" {
		var err error
		token, err = GenerateToken()
		if err != nil {
			return err
		}
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

// AddReturn adds a new token and returns the token string
func (s *TokenStore) AddReturn(token, label string, ttl time.Duration) (string, error) {
	if token == "" {
		var err error
		token, err = GenerateToken()
		if err != nil {
			return "", err
		}
	}
	if err := s.Add(token, label, ttl); err != nil {
		return "", err
	}
	return token, nil
}

// Remove removes a token and persists to disk
func (s *TokenStore) Remove(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.RemoveToken(token)
	return s.saveLocked()
}

// List returns all persisted tokens
func (s *TokenStore) List() []TokenRecord {
	list := s.v.ListTokens()
	out := make([]TokenRecord, 0, len(list))
	for _, t := range list {
		out = append(out, TokenRecord{
			Token:     t.Token,
			Label:     t.Label,
			CreatedAt: t.CreatedAt,
			ExpiresAt: t.ExpiresAt,
		})
	}
	return out
}

// Path returns tokens.json file path
func (s *TokenStore) Path() string { return s.path }
