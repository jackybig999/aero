// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — 用户中心领域模型与凭据加密工具
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

// User represents a registered middle-platform user or administrator.
type User struct {
	ID           uint64    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash,omitempty"`
	Phone        string    `json:"phone,omitempty"`
	Email        string    `json:"email,omitempty"`
	Status       bool      `json:"status"`
	IsStaff      bool      `json:"is_staff"`
	PlanName     string    `json:"plan_name,omitempty"`
	PlanMonths   int32     `json:"plan_months,omitempty"`
	PriceCents   int64     `json:"price_cents,omitempty"`
	SubSlug      string    `json:"sub_slug,omitempty"`
	SubToken     string    `json:"sub_token,omitempty"`
	ExpireAt     time.Time `json:"expire_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Sanitize returns a safe copy without sensitive password hashes.
func (u *User) Sanitize() *User {
	if u == nil {
		return nil
	}
	cp := *u
	cp.PasswordHash = ""
	return &cp
}

type TrafficStats struct {
	UserID     uint64     `json:"user_id"`
	UsedBytes  int64      `json:"used_bytes"`
	LimitBytes int64      `json:"limit_bytes"`
	ResetDate  *time.Time `json:"reset_date,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type CreateUserParams struct {
	Username   string
	Password   string
	Phone      string
	Email      string
	PlanName   string
	PlanMonths int32
	PriceCents int64
	IsStaff    bool
}

type UpdateUserParams struct {
	Phone      *string
	Email      *string
	Status     *bool
	IsStaff    *bool
	PlanName   *string
	PlanMonths *int32
	PriceCents *int64
}

func HashPassword(password string) string {
	salt := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))[:16]
	h := sha256.Sum256([]byte(salt + password))
	return fmt.Sprintf("sha256:%s:%x", salt, h)
}

func CheckPassword(password, stored string) bool {
	if len(stored) < 83 || stored[:7] != "sha256:" {
		return false
	}
	rest := stored[7:]
	idx := strings.IndexByte(rest, ':')
	if idx < 0 {
		return false
	}
	salt := rest[:idx]
	hash := rest[idx+1:]
	h := sha256.Sum256([]byte(salt + password))
	expected := fmt.Sprintf("%x", h)
	return subtle.ConstantTimeCompare([]byte(hash), []byte(expected)) == 1
}

func GenerateUserSlug(username string) string {
	clean := strings.ToLower(strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, username))
	if clean == "" {
		clean = "user"
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s%06x", clean, b)
}

func GenerateUserToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
