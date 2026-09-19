// Package service implements user-center business logic.
package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/store"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Service struct {
	store   store.Store
	hmacKey []byte
}

func New(s store.Store, hmacSecret string) *Service {
	return &Service{store: s, hmacKey: []byte(hmacSecret)}
}

// Register creates a user with hashed password.
func (s *Service) Register(params domain.CreateUserParams) (*domain.User, error) {
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
	u := &domain.User{
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

// Login validates credentials and returns a token.
func (s *Service) Login(username, password string) (string, *domain.User, error) {
	u, err := s.store.GetUserByUsername(username)
	if err != nil {
		return "", nil, ErrInvalidCredentials
	}
	if !u.Status {
		return "", nil, ErrInvalidCredentials
	}
	if !CheckPassword(password, u.PasswordHash) {
		return "", nil, ErrInvalidCredentials
	}
	token := s.issueToken(u.ID, u.Username, u.IsStaff)
	return token, u, nil
}

// HashPassword creates a salted SHA-256 hash.
// Format: "sha256:<hex_salt>:<hex_hash>"
func HashPassword(password string) string {
	salt := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))[:16]
	h := sha256.Sum256([]byte(salt + password))
	return fmt.Sprintf("sha256:%s:%x", salt, h)
}

// CheckPassword verifies a salted SHA-256 hash against the stored value.
func CheckPassword(password, stored string) bool {
	// Format: "sha256:<16_hex_salt>:<64_hex_hash>"
	if len(stored) < 83 || stored[:7] != "sha256:" {
		return false
	}
	rest := stored[7:]
	idx := -1
	for i, c := range rest {
		if c == ':' { idx = i; break }
	}
	if idx < 0 {
		return false
	}
	salt := rest[:idx]
	hash := rest[idx+1:]
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(salt+password)))
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1
}

func (s *Service) issueToken(userID uint64, username string, isStaff bool) string {
	payload := fmt.Sprintf("%d:%s:%t:%d", userID, username, isStaff, time.Now().Unix())
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

// VerifyToken checks a token and returns the UserID.
func (s *Service) VerifyToken(token string) (uint64, bool, error) {
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			payload := token[:i]
			sig := token[i+1:]
			mac := hmac.New(sha256.New, s.hmacKey)
			mac.Write([]byte(payload))
			expected := hex.EncodeToString(mac.Sum(nil))
			if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
				return 0, false, errors.New("invalid signature")
			}
			// payload = {uid}:{username}:{true|false}:{unix}
			parts := strings.Split(payload, ":")
			if len(parts) < 4 {
				return 0, false, errors.New("invalid payload")
			}
			uid, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				return 0, false, errors.New("invalid uid")
			}
			staffStr := parts[len(parts)-2]
			staff := staffStr == "true"
			return uid, staff, nil
		}
	}
	return 0, false, errors.New("invalid token")
}

func (s *Service) GetUser(id uint64) (*domain.User, error)      { return s.store.GetUser(id) }
func (s *Service) GetUserBySlug(slug string) (*domain.User, error) { return s.store.GetUserBySlug(slug) }
func (s *Service) ListUsers(p, ps int) ([]domain.User, int, error) {
	if p < 1 { p = 1 }
	if ps < 1 || ps > 100 { ps = 20 }
	return s.store.ListUsers(p, ps)
}
func (s *Service) UpdateUser(id uint64, email *string, st *bool, isStaff *bool) error {
	return s.store.UpdateUser(id, email, st, isStaff)
}
func (s *Service) UpdateUserFull(id uint64, p store.UpdateUserParams) error {
	return s.store.UpdateUserFull(id, p)
}
func (s *Service) RenewUser(id uint64, planName string, months int32, priceCents int64) (*domain.User, error) {
	return s.store.RenewUser(id, planName, months, priceCents)
}
func (s *Service) ResetSlug(id uint64) (string, error) {
	u, err := s.store.GetUser(id)
	if err != nil {
		return "", err
	}
	newSlug := GenerateUserSlug(u.Username)
	if err := s.store.ResetSlug(id, newSlug); err != nil {
		return "", err
	}
	return newSlug, nil
}
func (s *Service) DeleteUser(id uint64) error                          { return s.store.DeleteUser(id) }
func (s *Service) GetTraffic(uid uint64) (*domain.TrafficStats, error) { return s.store.GetTraffic(uid) }
func (s *Service) ListPlans(active bool) ([]domain.Plan, error)        { return s.store.ListPlans(active) }

// GenerateUserSlug 生成用户专属订阅 Slug: {username}{6位随机码}
func GenerateUserSlug(username string) string {
	clean := strings.ToLower(strings.TrimSpace(username))
	var sb strings.Builder
	for _, r := range clean {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	base := sb.String()
	if base == "" {
		base = "user"
	}
	return fmt.Sprintf("%s%s", base, randomCode(6))
}

func randomCode(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "a8b8c8"
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

func GenerateUserToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("usr_%s", hex.EncodeToString(b))
}

