// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package subscribe

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store 订阅落盘与内存缓存
type Store struct {
	mu   sync.RWMutex
	dir  string
	meta Meta
}

// NewStore 打开或创建 dir 下 sub_meta.json
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("empty data dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	path := s.metaPath()
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &s.meta); err != nil {
			return nil, fmt.Errorf("parse sub meta: %w", err)
		}
		return s, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Store) metaPath() string { return filepath.Join(s.dir, "sub_meta.json") }

// EnsureParams 写入/刷新订阅
type EnsureParams struct {
	Name     string
	Address  string
	Token    string
	SNI      string
	PinSPKI  []string
}

// Ensure 若无 secret 则生成；始终刷新节点字段并落盘 + client-sub.json
func (s *Store) Ensure(p EnsureParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.Name == "" {
		p.Name = "default"
	}
	if p.SNI == "" {
		p.SNI = "localhost"
	}

	srv := Server{
		Name:     p.Name,
		Address:  p.Address,
		Token:    p.Token,
		SNI:      p.SNI,
		Protocol: "tcp_h2",
		PinSPKI:  p.PinSPKI,
	}

	if s.meta.Secret == "" {
		sec, err := randomSecret(16)
		if err != nil {
			return err
		}
		s.meta.Secret = sec
	}
	doc := Document{
		Version:   "aero/2.0",
		CreatedAt: time.Now().Unix(),
		Servers:   []Server{srv},
	}
	// 强制签名：HMAC-SHA256(token)，与客户端 sub.Verify 一致
	doc.Signature = Sign(doc, []byte(p.Token))
	s.meta.Document = doc
	if err := s.saveLocked(); err != nil {
		return err
	}
	return s.writeClientSubLocked()
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(), data, 0o600)
}

func (s *Store) writeClientSubLocked() error {
	data, err := json.MarshalIndent(s.meta.Document, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "client-sub.json")
	return os.WriteFile(path, data, 0o644)
}

// Secret 订阅路径密钥
func (s *Store) Secret() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.meta.Secret
}

// Dir 数据目录
func (s *Store) Dir() string { return s.dir }

// DocumentJSON 订阅 JSON
func (s *Store) DocumentJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.meta.Document)
}

// Document 副本
func (s *Store) Document() Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.meta.Document
}

func randomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
