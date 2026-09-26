// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"
)

// Validator 管理有效的访问令牌，支持时间戳防重放和 Nonce 一次性校验
type Validator struct {
	mu     sync.RWMutex
	tokens map[string]*TokenInfo

	// nonceStore 记录已使用的 nonce，防止重放攻击
	// key: nonce hex string, value: 首次使用时间
	nonceStore map[string]time.Time
}

type TokenInfo struct {
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	Label     string
}

func NewValidator() *Validator {
	v := &Validator{
		tokens:     make(map[string]*TokenInfo),
		nonceStore: make(map[string]time.Time),
	}
	// 启动后台 goroutine 定期清理过期 nonce
	go v.cleanupLoop()
	return v
}

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

// Validate 仅验证 token 是否存在且未过期
func (v *Validator) Validate(token string) bool {
	v.mu.RLock()
	info, ok := v.tokens[token]
	v.mu.RUnlock()

	if !ok {
		return false
	}

	if time.Now().After(info.ExpiresAt) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(info.Token)) == 1
}

// ValidateWithTimestamp 验证 token + 时间戳（防重放，容忍 ±30 秒）
func (v *Validator) ValidateWithTimestamp(token string, timestamp uint64) bool {
	if !v.Validate(token) {
		return false
	}

	// 时间戳单位：毫秒
	ts := time.UnixMilli(int64(timestamp))
	diff := time.Since(ts)
	if diff < 0 {
		diff = -diff
	}
	// Browser CONNECT storms + slow handshake exceed 30s easily; 5m still blocks replay.
	if diff > 5*time.Minute {
		return false
	}

	return true
}

// maxNonces 限制内存，防 nonce 洪泛拖垮多用户节点
const maxNonces = 100_000

// ValidateFull 完整验证：token + 时间戳 + nonce
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
	// 超限时先清一波，仍满则拒绝（保服务）
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

// cleanupLoop 定期清理过期 nonce
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

func (v *Validator) RemoveToken(token string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.tokens, token)
}

// Clear 清空全部 token（重载前用；不影响 nonce 防重放）。
func (v *Validator) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tokens = make(map[string]*TokenInfo)
}

// Count 当前 token 数。
func (v *Validator) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.tokens)
}

func (v *Validator) ListTokens() []TokenInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var list []TokenInfo
	for _, info := range v.tokens {
		list = append(list, *info)
	}
	return list
}

// GenerateToken 生成随机令牌
func GenerateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("aero_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("aero_%x", b)
}
