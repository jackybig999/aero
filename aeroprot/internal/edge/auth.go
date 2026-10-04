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

// Validator validates access tokens, timestamps, and one-time nonces
type Validator struct {
	mu     sync.RWMutex
	tokens map[string]*TokenInfo

	// nonceStore maps nonce hex string -> first used time
	nonceStore map[string]time.Time
}

// NewValidator creates a new Validator
func NewValidator() *Validator {
	v := &Validator{
		tokens:     make(map[string]*TokenInfo),
		nonceStore: make(map[string]time.Time),
	}
	go v.cleanupLoop()
	return v
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

// ValidateWithTimestamp validates token + timestamp (anti-replay, tolerance ±5 minutes)
func (v *Validator) ValidateWithTimestamp(token string, timestamp uint64) bool {
	if !v.Validate(token) {
		return false
	}

	ts := time.UnixMilli(int64(timestamp))
	diff := time.Since(ts)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Minute {
		return false
	}

	return true
}

const maxNonces = 100_000

// ValidateFull validates token + timestamp + nonce
func (v *Validator) ValidateFull(token string, timestamp uint64, nonce []byte) bool {
	if !v.ValidateWithTimestamp(token, timestamp) {
		return false
	}
	if len(nonce) == 0 {
		return false
	}
	nonceKey := fmt.Sprintf("%x", nonce)

	v.mu.Lock()
	defer v.mu.Unlock()

	if _, used := v.nonceStore[nonceKey]; used {
		return false
	}

	if len(v.nonceStore) >= maxNonces {
		cutoff := time.Now().Add(-2 * time.Minute)
		for k, t := range v.nonceStore {
			if t.Before(cutoff) {
				delete(v.nonceStore, k)
			}
		}
		if len(v.nonceStore) >= maxNonces {
			return false
		}
	}
	v.nonceStore[nonceKey] = time.Now()
	return true
}

func (v *Validator) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		v.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, t := range v.nonceStore {
			if t.Before(cutoff) {
				delete(v.nonceStore, k)
			}
		}
		v.mu.Unlock()
	}
}

// RemoveToken removes token from in-memory validator
func (v *Validator) RemoveToken(token string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.tokens, token)
}

// Clear removes all tokens (used on reload)
func (v *Validator) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tokens = make(map[string]*TokenInfo)
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
	if err := s.loadInto(false); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload reloads tokens from disk into Validator
func (s *TokenStore) Reload() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Clear()
	if err := s.loadIntoLocked(true); err != nil {
		return 0, err
	}
	return s.v.Count(), nil
}

func (s *TokenStore) loadInto(clearFirst bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if clearFirst {
		s.v.Clear()
	}
	return s.loadIntoLocked(false)
}

func (s *TokenStore) loadIntoLocked(alreadyCleared bool) error {
	_ = alreadyCleared
	now := time.Now()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc tokenFileDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
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
