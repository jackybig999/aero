// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — 用户业务服务与 HMAC 会话 Token 校验
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// UserService coordinates user management, password hashing, and HMAC session tokens.
type UserService struct {
	store   UserStore
	hmacKey []byte
}

func NewUserService(store UserStore, hmacSecret string) *UserService {
	return &UserService{
		store:   store,
		hmacKey: []byte(hmacSecret),
	}
}

func (s *UserService) Register(params CreateUserParams) (*User, error) {
	if params.Username == "" || params.Password == "" {
		return nil, fmt.Errorf("username and password required")
	}
	slug := GenerateUserSlug(params.Username)
	token := GenerateUserToken()
	months := params.PlanMonths
	if months <= 0 {
		months = 1
	}
	planName := params.PlanName
	if planName == "" {
		if months == 3 {
			planName = "季度套餐"
		} else if months == 12 {
			planName = "年度套餐"
		} else {
			planName = "月度套餐"
		}
	}
	priceCents := params.PriceCents
	if priceCents <= 0 {
		if months == 3 {
			priceCents = 2499
		} else if months == 12 {
			priceCents = 7999
		} else {
			priceCents = 999
		}
	}
	expire := time.Now().AddDate(0, int(months), 0)
	if params.IsStaff {
		expire = time.Now().AddDate(10, 0, 0)
	}
	u := &User{
		Username:     params.Username,
		PasswordHash: HashPassword(params.Password),
		Phone:        params.Phone,
		Email:        params.Email,
		Status:       true,
		IsStaff:      params.IsStaff,
		PlanName:     planName,
		PlanMonths:   months,
		PriceCents:   priceCents,
		SubSlug:      slug,
		SubToken:     token,
		ExpireAt:     expire,
	}
	if _, err := s.store.CreateUser(u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserService) Login(username, password string) (string, *User, error) {
	u, err := s.store.GetUserByUsername(username)
	if err != nil || !u.Status || !CheckPassword(password, u.PasswordHash) {
		return "", nil, ErrInvalidCredentials
	}
	token := s.issueToken(u.ID, u.Username, u.IsStaff)
	return token, u, nil
}

func (s *UserService) GetUser(id uint64) (*User, error) {
	return s.store.GetUser(id)
}

func (s *UserService) ListUsers(page, pageSize int) ([]User, int, error) {
	return s.store.ListUsers(page, pageSize)
}

func (s *UserService) UpdateUserFull(id uint64, params UpdateUserParams) error {
	return s.store.UpdateUser(id, params)
}

func (s *UserService) RenewUser(id uint64, planName string, months int32, priceCents int64) (*User, error) {
	return s.store.Renew(id, planName, months, priceCents)
}

func (s *UserService) ResetSlug(id uint64) (string, error) {
	u, err := s.store.GetUser(id)
	if err != nil {
		return "", err
	}
	newSlug := GenerateUserSlug(u.Username)
	if err := s.store.UpdateSubSlug(id, newSlug); err != nil {
		return "", err
	}
	return newSlug, nil
}

func (s *UserService) DeleteUser(id uint64) error {
	return s.store.DeleteUser(id)
}

func (s *UserService) GetTraffic(id uint64) (*TrafficStats, error) {
	if _, err := s.store.GetUser(id); err != nil {
		return nil, err
	}
	return &TrafficStats{
		UserID:     id,
		UsedBytes:  0,
		LimitBytes: 100 * 1024 * 1024 * 1024,
		UpdatedAt:  time.Now(),
	}, nil
}

func (s *UserService) issueToken(userID uint64, username string, isStaff bool) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	staffStr := "0"
	if isStaff {
		staffStr = "1"
	}
	payload := fmt.Sprintf("%d:%s:%s:%s", userID, username, staffStr, ts)
	h := hmac.New(sha256.New, s.hmacKey)
	h.Write([]byte(payload))
	sig := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%s:%s", payload, sig)
}

func (s *UserService) VerifyToken(token string) (uint64, bool, error) {
	parts := strings.Split(token, ":")
	if len(parts) != 5 {
		return 0, false, errors.New("invalid token format")
	}
	uid, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, false, errors.New("invalid user id")
	}
	payload := strings.Join(parts[:4], ":")
	sig := parts[4]
	h := hmac.New(sha256.New, s.hmacKey)
	h.Write([]byte(payload))
	expected := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return 0, false, errors.New("invalid signature")
	}
	isStaff := parts[2] == "1"
	return uid, isStaff, nil
}
