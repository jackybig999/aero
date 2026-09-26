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
		if s.meta.UserSubs == nil {
			s.meta.UserSubs = make(map[string]UserSub)
		}
		return s, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	s.meta.UserSubs = make(map[string]UserSub)
	return s, nil
}

func (s *Store) metaPath() string { return filepath.Join(s.dir, "sub_meta.json") }

// EnsureParams 写入/刷新订阅
type EnsureParams struct {
	Name    string
	Address string
	Token   string
	SNI     string
	PinSPKI []string
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
		Protocol: "quic",
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

// UpsertUserSub 添加或更新用户专属订阅配置
func (s *Store) UpsertUserSub(sub UserSub) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta.UserSubs == nil {
		s.meta.UserSubs = make(map[string]UserSub)
	}
	if sub.Slug == "" {
		return fmt.Errorf("empty slug")
	}
	if sub.CreatedAt == 0 {
		sub.CreatedAt = time.Now().Unix()
	}
	// 若未指定具体节点，继承默认节点并将 token 替换为用户 token
	if len(sub.Servers) == 0 && len(s.meta.Document.Servers) > 0 {
		defaultSrv := s.meta.Document.Servers[0]
		defaultSrv.Token = sub.Token
		sub.Servers = []Server{defaultSrv}
	}
	// 计算用户订阅文档的 HMAC-SHA256 签名
	doc := Document{
		Version:   "aero/2.0",
		UserID:    sub.Username,
		ExpireAt:  sub.ExpireAt,
		Servers:   sub.Servers,
		CreatedAt: sub.CreatedAt,
	}
	if sub.Token != "" {
		sub.Signature = Sign(doc, []byte(sub.Token))
	}
	s.meta.UserSubs[sub.Slug] = sub
	return s.saveLocked()
}

// GetUserSub 根据 slug 获取用户订阅
func (s *Store) GetUserSub(slug string) (UserSub, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.meta.UserSubs == nil {
		return UserSub{}, false
	}
	sub, ok := s.meta.UserSubs[slug]
	return sub, ok
}

// ListUserSubs 列出所有用户订阅
func (s *Store) ListUserSubs() []UserSub {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserSub, 0, len(s.meta.UserSubs))
	for _, sub := range s.meta.UserSubs {
		out = append(out, sub)
	}
	return out
}

// DeleteUserSub 根据 slug 删除用户订阅
func (s *Store) DeleteUserSub(slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta.UserSubs == nil {
		return nil
	}
	delete(s.meta.UserSubs, slug)
	return s.saveLocked()
}

// UserDocumentJSON 序列化用户专属多节点订阅文档为 JSON
func (s *Store) UserDocumentJSON(sub UserSub) ([]byte, error) {
	doc := Document{
		Version:   "aero/2.0",
		UserID:    sub.Username,
		ExpireAt:  sub.ExpireAt,
		Signature: sub.Signature,
		Servers:   sub.Servers,
		CreatedAt: sub.CreatedAt,
	}
	return json.Marshal(doc)
}

func randomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
