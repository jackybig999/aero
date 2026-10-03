// Copyright 2026 AERO Protocol Contributors
// AERO User Center Subsystem (Models, Crypto, Store, Service & Handler)
package mid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

// ----------------------------------------------------------------------
// User Center Domain Models
// ----------------------------------------------------------------------

type User struct {
	ID            uint64          `json:"id"`
	UUID          string          `json:"uuid,omitempty"` // 专属短标识 (如 u_3fa8c1)
	Username      string          `json:"username"`
	PasswordHash  string          `json:"password_hash,omitempty"`
	Phone         string          `json:"phone,omitempty"`
	Email         string          `json:"email,omitempty"`
	Role          string          `json:"role,omitempty"`
	Status        bool            `json:"status"`
	IsStaff       bool            `json:"is_staff"`
	PlanName      string          `json:"plan_name,omitempty"`
	PlanMonths    int32           `json:"plan_months,omitempty"`
	PriceCents    int64           `json:"price_cents,omitempty"`
	SubSlug       string          `json:"sub_slug,omitempty"`
	SubToken      string          `json:"sub_token,omitempty"`
	SubTicketSeed string          `json:"sub_ticket_seed,omitempty"`
	AssignedNodes []string        `json:"assigned_nodes,omitempty"`
	Subscriptions []*Subscription `json:"subscriptions,omitempty"`
	ExpireAt      time.Time       `json:"expire_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func (u *User) Sanitize() *User {
	if u == nil {
		return nil
	}
	cp := *u
	cp.PasswordHash = ""
	return &cp
}

type TrafficStats struct {
	UserID          uint64     `json:"user_id"`
	UsedBytes       int64      `json:"used_bytes"`
	LimitBytes      int64      `json:"limit_bytes"`
	IsConnected     bool       `json:"is_connected"`
	LastConnectedAt *time.Time `json:"last_connected_at,omitempty"`
	ResetDate       *time.Time `json:"reset_date,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type Order struct {
	OrderNo       string     `json:"order_no"`
	UserID        uint64     `json:"user_id"`
	PlanID        uint64     `json:"plan_id"`
	PlanName      string     `json:"plan_name"`
	AssignedNodes []string   `json:"assigned_nodes"`
	AmountCents   int64      `json:"amount_cents"`
	PayChannel    string     `json:"pay_channel"`
	Status        string     `json:"status"` // pending | completed | closed
	CreatedAt     time.Time  `json:"created_at"`
	PaidAt        *time.Time `json:"paid_at,omitempty"`
}

type Subscription struct {
	SubID         string    `json:"sub_id"`          // e.g. sub_123lywo9x
	UserID        uint64    `json:"user_id"`         // 所属用户ID
	UserUUID      string    `json:"user_uuid"`       // 归属用户UUID
	SubSlug       string    `json:"sub_slug"`        // 订阅路径Slug: {username}{6位随机码}
	SubToken      string    `json:"sub_token"`       // 鉴权Token
	SubTicketSeed string    `json:"sub_ticket_seed"` // AES-GCM加密保护的认证种子
	PlanName      string    `json:"plan_name"`       // 关联套餐名
	AssignedNodes []string  `json:"assigned_nodes"`  // 绑定的专属节点列表
	LimitBytes    int64     `json:"limit_bytes"`     // 配额总流量 (字节)
	UsedBytes     int64     `json:"used_bytes"`      // 已使用流量 (字节)
	ExpireAt      time.Time `json:"expire_at"`       // 独立到期时间
	SwitchStatus  string    `json:"switch_status"`   // "on" / "off"
	Status        bool      `json:"status"`          // 启用状态 (true: 正常)
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func GenerateSubscriptionSlug(username string) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	rand6 := hex.EncodeToString(b) // 3 bytes = 6 hex chars
	cleanUser := strings.ToLower(strings.TrimSpace(username))
	if cleanUser == "" {
		cleanUser = "sub"
	}
	return fmt.Sprintf("%s%s", cleanUser, rand6)
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
	Username      *string
	Password      *string
	Phone         *string
	Email         *string
	Status        *bool
	IsStaff       *bool
	PlanName      *string
	PlanMonths    *int32
	PriceCents    *int64
	AssignedNodes *[]string
	ExpireAt      *time.Time
}

var (
	rxUsername = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)
	rxEmail    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

func ValidateUsername(u string) error {
	u = strings.TrimSpace(u)
	if len(u) < 3 || len(u) > 32 {
		return errors.New("用户名长度须在3至32位之间")
	}
	if !rxUsername.MatchString(u) {
		return errors.New("用户名仅支持英文字母、数字和下划线组合")
	}
	return nil
}

func ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.New("电子邮箱为必填项")
	}
	if !rxEmail.MatchString(email) {
		return errors.New("请输入合法的电子邮箱格式")
	}
	return nil
}

func ValidatePassword(p string) error {
	p = strings.TrimSpace(p)
	if len(p) < 8 {
		return errors.New("密码长度至少为8位")
	}
	hasLetter := false
	hasDigit := false
	for _, c := range p {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		} else if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return errors.New("密码必须包含字母和数字的组合")
	}
	return nil
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

func GenerateTicketSeed() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "sec_" + hex.EncodeToString(b)
}

func DeriveNodeToken(seed, domain string) string {
	if seed == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(seed + ":" + strings.ToLower(strings.TrimSpace(domain))))
	return "tok_" + hex.EncodeToString(h.Sum(nil))[:24]
}

func GenerateShortUUID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("u_%06x", b)
}

func EncryptTicketSeed(plainSeed, secretKey string) string {
	if plainSeed == "" {
		return ""
	}
	key := sha256.Sum256([]byte(secretKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return plainSeed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plainSeed
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plainSeed
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plainSeed), nil)
	return "enc_" + hex.EncodeToString(ciphertext)
}

func DecryptTicketSeed(encSeed, secretKey string) string {
	if !strings.HasPrefix(encSeed, "enc_") {
		return encSeed
	}
	rawHex := strings.TrimPrefix(encSeed, "enc_")
	data, err := hex.DecodeString(rawHex)
	if err != nil {
		return ""
	}
	key := sha256.Sum256([]byte(secretKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ""
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

// ----------------------------------------------------------------------
// UserStore Interface
// ----------------------------------------------------------------------

type UserStore interface {
	CreateUser(u *User) (uint64, error)
	GetUser(id uint64) (*User, error)
	GetUserByUsername(username string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserBySlug(slug string) (*User, error)
	ListUsers(page, pageSize int) ([]User, int, error)
	UpdateUser(id uint64, params UpdateUserParams) error
	DeleteUser(id uint64) error
	SetStaff(id uint64, isStaff bool) error
	SetPassword(id uint64, hash string) error
	UpdateSubSlug(id uint64, slug string) error
	Renew(id uint64, planName string, months int32, priceCents int64) (*User, error)
	CreateOrder(order *Order) error
	ListOrders(userID uint64) ([]Order, error)
	UpdateOrderStatus(orderNo string, status string) error
	GetTraffic(id uint64) (*TrafficStats, error)
	UpdateTraffic(id uint64, usedBytes, limitBytes int64) error
	CreateSubscription(sub *Subscription) error
	GetSubscription(subID string) (*Subscription, error)
	GetSubscriptionBySlug(slug string) (*Subscription, error)
	ListSubscriptions(userID uint64) ([]*Subscription, error)
	RenewSubscription(subID string, months int32, priceCents int64, planName string) (*Subscription, error)
	UpdateSubscription(subID string, status bool, assignedNodes []string) error
	UpdateSubscriptionSwitch(subID string, switchStatus string) error
	DeleteSubscription(subID string) error
}

// ----------------------------------------------------------------------
// FileUserStore (JSON Persistence)
// ----------------------------------------------------------------------

type FileUserStore struct {
	mu            sync.RWMutex
	path          string
	users         map[uint64]*User
	orders        map[string]*Order
	traffic       map[uint64]*TrafficStats
	subscriptions map[string]*Subscription
	nextID        uint64
}

func NewFileUserStore(path string) (*FileUserStore, error) {
	s := &FileUserStore{
		path:          path,
		users:         make(map[uint64]*User),
		orders:        make(map[string]*Order),
		traffic:       make(map[uint64]*TrafficStats),
		subscriptions: make(map[string]*Subscription),
		nextID:        1,
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *FileUserStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	data = []byte(strings.ReplaceAll(string(data), `"expire_at": ""`, `"expire_at": null`))
	var list []*User
	if err := json.Unmarshal(data, &list); err == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, u := range list {
			s.users[u.ID] = u
			if u.ID >= s.nextID {
				s.nextID = u.ID + 1
			}
		}
		return nil
	}

	var wrapper struct {
		NextID        uint64                   `json:"next_id"`
		Users         map[string]*User         `json:"users"`
		Orders        []*Order                 `json:"orders,omitempty"`
		Traffic       map[string]*TrafficStats `json:"traffic,omitempty"`
		Subscriptions []*Subscription          `json:"subscriptions,omitempty"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID = wrapper.NextID
	if s.nextID == 0 {
		s.nextID = 1
	}
	for idStr, u := range wrapper.Users {
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err == nil {
			s.users[id] = u
			if id >= s.nextID {
				s.nextID = id + 1
			}
		}
	}
	for _, o := range wrapper.Orders {
		s.orders[o.OrderNo] = o
	}
	for uidStr, t := range wrapper.Traffic {
		uid, err := strconv.ParseUint(uidStr, 10, 64)
		if err == nil {
			s.traffic[uid] = t
		}
	}
	for _, sub := range wrapper.Subscriptions {
		s.subscriptions[sub.SubID] = sub
	}
	return nil
}

func (s *FileUserStore) save() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var orders []*Order
	for _, o := range s.orders {
		orders = append(orders, o)
	}
	var subs []*Subscription
	for _, sub := range s.subscriptions {
		subs = append(subs, sub)
	}

	wrapper := struct {
		NextID        uint64                   `json:"next_id"`
		Users         map[string]*User         `json:"users"`
		Orders        []*Order                 `json:"orders"`
		Traffic       map[string]*TrafficStats `json:"traffic"`
		Subscriptions []*Subscription          `json:"subscriptions"`
	}{
		NextID:        s.nextID,
		Users:         make(map[string]*User),
		Orders:        orders,
		Traffic:       make(map[string]*TrafficStats),
		Subscriptions: subs,
	}
	for id, u := range s.users {
		wrapper.Users[strconv.FormatUint(id, 10)] = u
	}
	for uid, t := range s.traffic {
		wrapper.Traffic[strconv.FormatUint(uid, 10)] = t
	}

	data, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileUserStore) CreateUser(u *User) (uint64, error) {
	s.mu.Lock()
	id := s.nextID
	s.nextID++
	u.ID = id
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	s.users[id] = u
	s.mu.Unlock()
	_ = s.save()
	return id, nil
}

func (s *FileUserStore) GetUser(id uint64) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	cp := *u
	return &cp, nil
}

func (s *FileUserStore) GetUserByUsername(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	target := strings.ToLower(strings.TrimSpace(username))
	for _, u := range s.users {
		if strings.ToLower(u.Username) == target {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *FileUserStore) GetUserByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	target := strings.ToLower(strings.TrimSpace(email))
	for _, u := range s.users {
		if strings.ToLower(u.Email) == target {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *FileUserStore) GetUserBySlug(slug string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.SubSlug == slug {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *FileUserStore) ListUsers(page, pageSize int) ([]User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []User
	for _, u := range s.users {
		all = append(all, *u)
	}
	total := len(all)
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []User{}, total, nil
	}
	end := offset + pageSize
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

func (s *FileUserStore) UpdateUser(id uint64, params UpdateUserParams) error {
	s.mu.Lock()
	u, ok := s.users[id]
	if !ok {
		s.mu.Unlock()
		return errors.New("user not found")
	}
	if params.Username != nil {
		u.Username = *params.Username
	}
	if params.Password != nil {
		u.PasswordHash = HashPassword(*params.Password)
	}
	if params.Phone != nil {
		u.Phone = *params.Phone
	}
	if params.Email != nil {
		u.Email = *params.Email
	}
	if params.Status != nil {
		u.Status = *params.Status
	}
	if params.IsStaff != nil {
		u.IsStaff = *params.IsStaff
	}
	if params.PlanName != nil {
		u.PlanName = *params.PlanName
	}
	if params.PlanMonths != nil {
		u.PlanMonths = *params.PlanMonths
	}
	if params.PriceCents != nil {
		u.PriceCents = *params.PriceCents
	}
	if params.AssignedNodes != nil {
		u.AssignedNodes = *params.AssignedNodes
	}
	if params.ExpireAt != nil {
		u.ExpireAt = *params.ExpireAt
	}
	u.UpdatedAt = time.Now()
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) DeleteUser(id uint64) error {
	s.mu.Lock()
	delete(s.users, id)
	delete(s.traffic, id)
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) SetStaff(id uint64, isStaff bool) error {
	s.mu.Lock()
	if u, ok := s.users[id]; ok {
		u.IsStaff = isStaff
		u.UpdatedAt = time.Now()
	}
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) SetPassword(id uint64, hash string) error {
	s.mu.Lock()
	if u, ok := s.users[id]; ok {
		u.PasswordHash = hash
		u.UpdatedAt = time.Now()
	}
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) UpdateSubSlug(id uint64, slug string) error {
	s.mu.Lock()
	if u, ok := s.users[id]; ok {
		u.SubSlug = slug
		u.UpdatedAt = time.Now()
	}
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) Renew(id uint64, planName string, months int32, priceCents int64) (*User, error) {
	s.mu.Lock()
	u, ok := s.users[id]
	if !ok {
		s.mu.Unlock()
		return nil, errors.New("user not found")
	}
	now := time.Now()
	base := now
	if u.ExpireAt.After(now) {
		base = u.ExpireAt
	}
	u.ExpireAt = base.AddDate(0, int(months), 0)
	if planName != "" {
		u.PlanName = planName
	}
	if priceCents > 0 {
		u.PriceCents = priceCents
	}
	u.PlanMonths = months
	u.Status = true
	u.UpdatedAt = now
	cp := *u
	s.mu.Unlock()
	_ = s.save()
	return &cp, nil
}

func (s *FileUserStore) CreateOrder(order *Order) error {
	s.mu.Lock()
	s.orders[order.OrderNo] = order
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) ListOrders(userID uint64) ([]Order, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []Order
	for _, o := range s.orders {
		if userID == 0 || o.UserID == userID {
			list = append(list, *o)
		}
	}
	return list, nil
}

func (s *FileUserStore) UpdateOrderStatus(orderNo string, status string) error {
	s.mu.Lock()
	if o, ok := s.orders[orderNo]; ok {
		o.Status = status
		now := time.Now()
		if status == "completed" {
			o.PaidAt = &now
		}
	}
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) GetTraffic(id uint64) (*TrafficStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.traffic[id]
	if !ok {
		return &TrafficStats{
			UserID:      id,
			UsedBytes:   0,
			LimitBytes:  107374182400,
			IsConnected: false,
			UpdatedAt:   time.Now(),
		}, nil
	}
	cp := *t
	return &cp, nil
}

func (s *FileUserStore) UpdateTraffic(id uint64, usedBytes, limitBytes int64) error {
	s.mu.Lock()
	t, ok := s.traffic[id]
	if !ok {
		t = &TrafficStats{
			UserID:     id,
			LimitBytes: 107374182400,
			UpdatedAt:  time.Now(),
		}
		s.traffic[id] = t
	}
	if usedBytes >= 0 {
		t.UsedBytes = usedBytes
	}
	if limitBytes > 0 || limitBytes == -1 {
		t.LimitBytes = limitBytes
	}
	t.UpdatedAt = time.Now()
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) CreateSubscription(sub *Subscription) error {
	s.mu.Lock()
	s.subscriptions[sub.SubID] = sub
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) GetSubscription(subID string) (*Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.subscriptions[subID]
	if !ok {
		return nil, errors.New("subscription not found")
	}
	cp := *sub
	return &cp, nil
}

func (s *FileUserStore) GetSubscriptionBySlug(slug string) (*Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sub := range s.subscriptions {
		if sub.SubSlug == slug {
			cp := *sub
			return &cp, nil
		}
	}
	return nil, errors.New("subscription not found")
}

func (s *FileUserStore) ListSubscriptions(userID uint64) ([]*Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*Subscription
	for _, sub := range s.subscriptions {
		if userID == 0 || sub.UserID == userID {
			cp := *sub
			list = append(list, &cp)
		}
	}
	return list, nil
}

func (s *FileUserStore) RenewSubscription(subID string, months int32, priceCents int64, planName string) (*Subscription, error) {
	s.mu.Lock()
	sub, ok := s.subscriptions[subID]
	if !ok {
		s.mu.Unlock()
		return nil, errors.New("subscription not found")
	}
	now := time.Now()
	base := now
	if sub.ExpireAt.After(now) {
		base = sub.ExpireAt
	}
	sub.ExpireAt = base.AddDate(0, int(months), 0)
	if planName != "" {
		sub.PlanName = planName
	}
	sub.Status = true
	sub.SwitchStatus = "on"
	sub.UpdatedAt = now
	cp := *sub
	s.mu.Unlock()
	_ = s.save()
	return &cp, nil
}

func (s *FileUserStore) UpdateSubscription(subID string, status bool, assignedNodes []string) error {
	s.mu.Lock()
	sub, ok := s.subscriptions[subID]
	if !ok {
		s.mu.Unlock()
		return errors.New("subscription not found")
	}
	sub.Status = status
	sub.AssignedNodes = assignedNodes
	sub.UpdatedAt = time.Now()
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) UpdateSubscriptionSwitch(subID string, switchStatus string) error {
	s.mu.Lock()
	sub, ok := s.subscriptions[subID]
	if !ok {
		s.mu.Unlock()
		return errors.New("subscription not found")
	}
	sub.SwitchStatus = switchStatus
	sub.UpdatedAt = time.Now()
	s.mu.Unlock()
	return s.save()
}

func (s *FileUserStore) DeleteSubscription(subID string) error {
	s.mu.Lock()
	delete(s.subscriptions, subID)
	s.mu.Unlock()
	return s.save()
}

// ----------------------------------------------------------------------
// MemoryUserStore (In-Memory for Testing)
// ----------------------------------------------------------------------

type MemoryUserStore struct {
	mu            sync.RWMutex
	users         map[uint64]*User
	orders        map[string]*Order
	traffic       map[uint64]*TrafficStats
	subscriptions map[string]*Subscription
	nextID        uint64
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users:         make(map[uint64]*User),
		orders:        make(map[string]*Order),
		traffic:       make(map[uint64]*TrafficStats),
		subscriptions: make(map[string]*Subscription),
		nextID:        1,
	}
}

func (m *MemoryUserStore) CreateUser(u *User) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextID
	m.nextID++
	u.ID = id
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	m.users[id] = u
	return id, nil
}

func (m *MemoryUserStore) GetUser(id uint64) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	cp := *u
	return &cp, nil
}

func (m *MemoryUserStore) GetUserByUsername(username string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	target := strings.ToLower(strings.TrimSpace(username))
	for _, u := range m.users {
		if strings.ToLower(u.Username) == target {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("user not found")
}

func (m *MemoryUserStore) GetUserByEmail(email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	target := strings.ToLower(strings.TrimSpace(email))
	for _, u := range m.users {
		if strings.ToLower(u.Email) == target {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("user not found")
}

func (m *MemoryUserStore) GetUserBySlug(slug string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.SubSlug == slug {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("user not found")
}

func (m *MemoryUserStore) ListUsers(page, pageSize int) ([]User, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []User
	for _, u := range m.users {
		all = append(all, *u)
	}
	total := len(all)
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []User{}, total, nil
	}
	end := offset + pageSize
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

func (m *MemoryUserStore) UpdateUser(id uint64, params UpdateUserParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return errors.New("user not found")
	}
	if params.Username != nil {
		u.Username = *params.Username
	}
	if params.Password != nil {
		u.PasswordHash = HashPassword(*params.Password)
	}
	if params.Phone != nil {
		u.Phone = *params.Phone
	}
	if params.Email != nil {
		u.Email = *params.Email
	}
	if params.Status != nil {
		u.Status = *params.Status
	}
	if params.IsStaff != nil {
		u.IsStaff = *params.IsStaff
	}
	if params.PlanName != nil {
		u.PlanName = *params.PlanName
	}
	if params.PlanMonths != nil {
		u.PlanMonths = *params.PlanMonths
	}
	if params.PriceCents != nil {
		u.PriceCents = *params.PriceCents
	}
	if params.AssignedNodes != nil {
		u.AssignedNodes = *params.AssignedNodes
	}
	if params.ExpireAt != nil {
		u.ExpireAt = *params.ExpireAt
	}
	u.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryUserStore) DeleteUser(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, id)
	delete(m.traffic, id)
	return nil
}

func (m *MemoryUserStore) SetStaff(id uint64, isStaff bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[id]; ok {
		u.IsStaff = isStaff
		u.UpdatedAt = time.Now()
	}
	return nil
}

func (m *MemoryUserStore) SetPassword(id uint64, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[id]; ok {
		u.PasswordHash = hash
		u.UpdatedAt = time.Now()
	}
	return nil
}

func (m *MemoryUserStore) UpdateSubSlug(id uint64, slug string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[id]; ok {
		u.SubSlug = slug
		u.UpdatedAt = time.Now()
	}
	return nil
}

func (m *MemoryUserStore) Renew(id uint64, planName string, months int32, priceCents int64) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	now := time.Now()
	base := now
	if u.ExpireAt.After(now) {
		base = u.ExpireAt
	}
	u.ExpireAt = base.AddDate(0, int(months), 0)
	if planName != "" {
		u.PlanName = planName
	}
	if priceCents > 0 {
		u.PriceCents = priceCents
	}
	u.PlanMonths = months
	u.Status = true
	u.UpdatedAt = now
	cp := *u
	return &cp, nil
}

func (m *MemoryUserStore) CreateOrder(order *Order) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orders[order.OrderNo] = order
	return nil
}

func (m *MemoryUserStore) ListOrders(userID uint64) ([]Order, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []Order
	for _, o := range m.orders {
		if userID == 0 || o.UserID == userID {
			list = append(list, *o)
		}
	}
	return list, nil
}

func (m *MemoryUserStore) UpdateOrderStatus(orderNo string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.orders[orderNo]; ok {
		o.Status = status
		now := time.Now()
		if status == "completed" {
			o.PaidAt = &now
		}
	}
	return nil
}

func (m *MemoryUserStore) GetTraffic(id uint64) (*TrafficStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.traffic[id]
	if !ok {
		return &TrafficStats{
			UserID:      id,
			UsedBytes:   0,
			LimitBytes:  107374182400,
			IsConnected: false,
			UpdatedAt:   time.Now(),
		}, nil
	}
	cp := *t
	return &cp, nil
}

func (m *MemoryUserStore) UpdateTraffic(id uint64, usedBytes, limitBytes int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.traffic[id]
	if !ok {
		t = &TrafficStats{
			UserID:     id,
			LimitBytes: 107374182400,
			UpdatedAt:  time.Now(),
		}
		m.traffic[id] = t
	}
	if usedBytes >= 0 {
		t.UsedBytes = usedBytes
	}
	if limitBytes > 0 || limitBytes == -1 {
		t.LimitBytes = limitBytes
	}
	t.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryUserStore) CreateSubscription(sub *Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscriptions[sub.SubID] = sub
	return nil
}

func (m *MemoryUserStore) GetSubscription(subID string) (*Subscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sub, ok := m.subscriptions[subID]
	if !ok {
		return nil, errors.New("subscription not found")
	}
	cp := *sub
	return &cp, nil
}

func (m *MemoryUserStore) GetSubscriptionBySlug(slug string) (*Subscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, sub := range m.subscriptions {
		if sub.SubSlug == slug {
			cp := *sub
			return &cp, nil
		}
	}
	return nil, errors.New("subscription not found")
}

func (m *MemoryUserStore) ListSubscriptions(userID uint64) ([]*Subscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*Subscription
	for _, sub := range m.subscriptions {
		if userID == 0 || sub.UserID == userID {
			cp := *sub
			list = append(list, &cp)
		}
	}
	return list, nil
}

func (m *MemoryUserStore) RenewSubscription(subID string, months int32, priceCents int64, planName string) (*Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sub, ok := m.subscriptions[subID]
	if !ok {
		return nil, errors.New("subscription not found")
	}
	now := time.Now()
	base := now
	if sub.ExpireAt.After(now) {
		base = sub.ExpireAt
	}
	sub.ExpireAt = base.AddDate(0, int(months), 0)
	if planName != "" {
		sub.PlanName = planName
	}
	sub.Status = true
	sub.SwitchStatus = "on"
	sub.UpdatedAt = now
	cp := *sub
	return &cp, nil
}

func (m *MemoryUserStore) UpdateSubscription(subID string, status bool, assignedNodes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sub, ok := m.subscriptions[subID]
	if !ok {
		return errors.New("subscription not found")
	}
	sub.Status = status
	sub.AssignedNodes = assignedNodes
	sub.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryUserStore) UpdateSubscriptionSwitch(subID string, switchStatus string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sub, ok := m.subscriptions[subID]
	if !ok {
		return errors.New("subscription not found")
	}
	sub.SwitchStatus = switchStatus
	sub.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryUserStore) DeleteSubscription(subID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subscriptions, subID)
	return nil
}

// ----------------------------------------------------------------------
// UserService
// ----------------------------------------------------------------------

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
	if err := ValidateUsername(params.Username); err != nil {
		return nil, err
	}
	if !params.IsStaff {
		if err := ValidateEmail(params.Email); err != nil {
			return nil, err
		}
	} else if params.Email != "" {
		if err := ValidateEmail(params.Email); err != nil {
			return nil, err
		}
	}
	if err := ValidatePassword(params.Password); err != nil {
		return nil, err
	}

	if existing, err := s.store.GetUserByUsername(params.Username); err == nil && existing != nil {
		return nil, errors.New("该用户名已被注册")
	}
	if params.Email != "" {
		if existingEmail, err := s.store.GetUserByEmail(params.Email); err == nil && existingEmail != nil {
			return nil, errors.New("该电子邮箱已被绑定")
		}
	}

	slug := GenerateUserSlug(params.Username)
	token := GenerateUserToken()

	var expire time.Time
	planName := strings.TrimSpace(params.PlanName)
	months := params.PlanMonths
	priceCents := params.PriceCents

	if params.IsStaff {
		planName = "系统管理"
		months = 120
		expire = time.Now().AddDate(10, 0, 0)
	} else if planName != "" && months > 0 {
		expire = time.Now().AddDate(0, int(months), 0)
	}

	u := &User{
		UUID:          GenerateShortUUID(),
		Username:      params.Username,
		PasswordHash:  HashPassword(params.Password),
		Phone:         params.Phone,
		Email:         params.Email,
		Status:        true,
		IsStaff:       params.IsStaff,
		PlanName:      planName,
		PlanMonths:    months,
		PriceCents:    priceCents,
		SubSlug:       slug,
		SubToken:      token,
		SubTicketSeed: GenerateTicketSeed(),
		AssignedNodes: []string{},
		ExpireAt:      expire,
	}
	createdID, err := s.store.CreateUser(u)
	if err != nil {
		return nil, err
	}
	u.ID = createdID
	return u, nil
}

func (s *UserService) Login(username, password string) (string, *User, error) {
	u, err := s.store.GetUserByUsername(username)
	if err != nil || !u.Status || !CheckPassword(password, u.PasswordHash) {
		return "", nil, ErrInvalidCredentials
	}
	token := s.GenerateSessionToken(u)
	return token, u.Sanitize(), nil
}

func (s *UserService) GenerateSessionToken(u *User) string {
	expire := time.Now().Add(7 * 24 * time.Hour).Unix()
	payload := fmt.Sprintf("%d:%t:%d", u.ID, u.IsStaff, expire)
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s:%s", payload, sig)
}

func (s *UserService) VerifyToken(token string) (uint64, bool, error) {
	parts := strings.Split(token, ":")
	if len(parts) != 4 {
		return 0, false, errors.New("malformed token")
	}
	payload := strings.Join(parts[:3], ":")
	sig := parts[3]

	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return 0, false, errors.New("invalid signature")
	}

	expire, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > expire {
		return 0, false, errors.New("token expired")
	}

	uid, _ := strconv.ParseUint(parts[0], 10, 64)
	isStaff := parts[1] == "true"
	return uid, isStaff, nil
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

func (s *UserService) GetUser(id uint64) (*User, error) {
	return s.store.GetUser(id)
}

func (s *UserService) GetUserByUsername(username string) (*User, error) {
	return s.store.GetUserByUsername(username)
}

func (s *UserService) GetUserByEmail(email string) (*User, error) {
	return s.store.GetUserByEmail(email)
}

func (s *UserService) GetUserBySlug(slug string) (*User, error) {
	return s.store.GetUserBySlug(slug)
}

func (s *UserService) ListUsers(page, pageSize int) ([]User, int, error) {
	return s.store.ListUsers(page, pageSize)
}

func (s *UserService) UpdateUser(id uint64, params UpdateUserParams) error {
	return s.store.UpdateUser(id, params)
}

func (s *UserService) UpdateUserFull(id uint64, params UpdateUserParams) error {
	return s.store.UpdateUser(id, params)
}

func (s *UserService) ListSubscriptions(userID uint64) ([]*Subscription, error) {
	return s.store.ListSubscriptions(userID)
}

func (s *UserService) CreateSubscription(sub *Subscription) error {
	return s.store.CreateSubscription(sub)
}

func (s *UserService) UpdateSubscriptionSwitch(subID string, switchStatus string) error {
	return s.store.UpdateSubscriptionSwitch(subID, switchStatus)
}

func (s *UserService) DeleteSubscription(subID string) error {
	return s.store.DeleteSubscription(subID)
}

func (s *UserService) RenewSubscription(subID string, months int32, priceCents int64, planName string) (*Subscription, error) {
	return s.store.RenewSubscription(subID, months, priceCents, planName)
}

func (s *UserService) Store() UserStore {
	return s.store
}

func (s *UserService) DeleteUser(id uint64) error {
	return s.store.DeleteUser(id)
}

func (s *UserService) GetTraffic(id uint64) (*TrafficStats, error) {
	return s.store.GetTraffic(id)
}

func (s *UserService) SetStaff(id uint64, isStaff bool) error {
	return s.store.SetStaff(id, isStaff)
}

func (s *UserService) SetPassword(id uint64, newPwd string) error {
	if err := ValidatePassword(newPwd); err != nil {
		return err
	}
	return s.store.SetPassword(id, HashPassword(newPwd))
}

// ----------------------------------------------------------------------
// UserHandler
// ----------------------------------------------------------------------

type UserHandler struct {
	svc *UserService
	sb  *SubBuilder
}

func NewUserHandler(svc *UserService) *UserHandler {
	return &UserHandler{svc: svc}
}

func (h *UserHandler) SetSubBuilder(sb *SubBuilder) {
	h.sb = sb
}

func (h *UserHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login/", h.Login)
	mux.HandleFunc("GET /api/v1/user/subscription/", h.GetMySubscription)
	mux.HandleFunc("POST /api/v1/users/", h.CreateUser)
	mux.HandleFunc("GET /api/v1/users/", h.ListUsers)
	mux.HandleFunc("GET /api/v1/users/{id}/", h.GetUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}/", h.UpdateUser)
	mux.HandleFunc("PUT /api/v1/users/{id}/", h.UpdateUser)
	mux.HandleFunc("POST /api/v1/users/{id}/renew/", h.RenewUser)
	mux.HandleFunc("POST /api/v1/users/{id}/reset-slug/", h.ResetSlug)
	mux.HandleFunc("DELETE /api/v1/users/{id}/", h.DeleteUser)
	mux.HandleFunc("GET /api/v1/users/{id}/traffic/", h.GetTraffic)
	mux.HandleFunc("GET /api/v1/subscriptions/", h.ListSubscriptions)
	mux.HandleFunc("POST /api/v1/users/{id}/subscriptions/", h.CreateUserSubscription)
	mux.HandleFunc("POST /api/v1/subscriptions/{id}/switch/", h.SwitchSubscription)
	mux.HandleFunc("DELETE /api/v1/subscriptions/{id}/", h.DeleteSubscription)
	mux.HandleFunc("POST /api/v1/subscriptions/{id}/renew/", h.RenewSubscription)
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Phone      string `json:"phone"`
		Email      string `json:"email"`
		PlanName   string `json:"plan_name"`
		PlanMonths int32  `json:"plan_months"`
		PriceCents int64  `json:"price_cents"`
		IsStaff    bool   `json:"is_staff"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid body"})
		return
	}
	u, err := h.svc.Register(CreateUserParams{
		Username:   req.Username,
		Password:   req.Password,
		Phone:      req.Phone,
		Email:      req.Email,
		PlanName:   req.PlanName,
		PlanMonths: req.PlanMonths,
		PriceCents: req.PriceCents,
		IsStaff:    req.IsStaff,
	})
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Portal   string `json:"portal"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	token, user, err := h.svc.Login(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 1003, "message": "invalid credentials"})
		return
	}
	if req.Portal == "user" && user.IsStaff {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 1003, "message": "管理员账号禁止在普通用户端登录"})
		return
	}
	if req.Portal == "admin" && !user.IsStaff {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 1003, "message": "非管理员账号禁止访问管理后台"})
		return
	}
	loginData := map[string]any{
		"token":          token,
		"user":           user,
		"id":             user.ID,
		"uuid":           user.UUID,
		"username":       user.Username,
		"is_staff":       user.IsStaff,
		"role":           user.Role,
		"sub_slug":       user.SubSlug,
		"slug":           user.SubSlug,
		"sub_token":      user.SubToken,
		"token_secret":   user.SubToken,
		"assigned_nodes": user.AssignedNodes,
		"plan_name":      user.PlanName,
		"expire_at":      user.ExpireAt,
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": loginData,
	})
}

func (h *UserHandler) GetMySubscription(w http.ResponseWriter, r *http.Request) {
	uid, ok := r.Context().Value(CtxUserID).(uint64)
	if !ok || uid == 0 {
		writeJSON(w, http.StatusUnauthorized, errResp(1003, "unauthorized"))
		return
	}
	if h.sb != nil {
		h.sb.ServePrivateSub(w, r)
		return
	}
	u, err := h.svc.GetUser(uid)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errResp(1001, "user not found"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": map[string]any{
			"slug":      u.SubSlug,
			"token":     u.SubToken,
			"plan_name": u.PlanName,
			"expire_at": u.ExpireAt,
		},
	})
}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	list, total, err := h.svc.ListUsers(page, pageSize)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	sanitized := make([]*User, len(list))
	for i := range list {
		sanitized[i] = list[i].Sanitize()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": map[string]any{
			"total":     total,
			"page":      page,
			"page_size": pageSize,
			"results":   sanitized,
		},
	})
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	u, err := h.svc.GetUser(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		Username      *string   `json:"username"`
		Password      *string   `json:"password"`
		Phone         *string   `json:"phone"`
		Email         *string   `json:"email"`
		Status        *bool     `json:"status"`
		IsStaff       *bool     `json:"is_staff"`
		PlanName      *string   `json:"plan_name"`
		PlanMonths    *int32    `json:"plan_months"`
		PriceCents    *int64    `json:"price_cents"`
		AssignedNodes *[]string `json:"assigned_nodes"`
		ExpireAt      *string   `json:"expire_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid body"})
		return
	}

	params := UpdateUserParams{
		Username:      req.Username,
		Password:      req.Password,
		Phone:         req.Phone,
		Email:         req.Email,
		Status:        req.Status,
		IsStaff:       req.IsStaff,
		PlanName:      req.PlanName,
		PlanMonths:    req.PlanMonths,
		PriceCents:    req.PriceCents,
		AssignedNodes: req.AssignedNodes,
	}
	if req.ExpireAt != nil {
		if t, err := time.Parse(time.RFC3339, *req.ExpireAt); err == nil {
			params.ExpireAt = &t
		}
	}

	if err := h.svc.UpdateUser(id, params); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "success"})
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	_ = h.svc.DeleteUser(id)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "success"})
}

func (h *UserHandler) RenewUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		PlanName   string `json:"plan_name"`
		PlanMonths int32  `json:"plan_months"`
		PriceCents int64  `json:"price_cents"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.PlanMonths <= 0 {
		req.PlanMonths = 1
	}
	u, err := h.svc.RenewUser(id, req.PlanName, req.PlanMonths, req.PriceCents)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *UserHandler) ResetSlug(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	newSlug, err := h.svc.ResetSlug(id)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]string{"sub_slug": newSlug}})
}

func (h *UserHandler) GetTraffic(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	ts, _ := h.svc.GetTraffic(id)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": ts})
}

func (h *UserHandler) ListSubscriptions(w http.ResponseWriter, r *http.Request) {
	uidStr := r.URL.Query().Get("user_id")
	var uid uint64
	if uidStr != "" {
		uid, _ = strconv.ParseUint(uidStr, 10, 64)
	}
	subs, err := h.svc.store.ListSubscriptions(uid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	if subs == nil {
		subs = []*Subscription{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": map[string]any{"results": subs},
	})
}

func (h *UserHandler) CreateUserSubscription(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	u, err := h.svc.GetUser(userID)
	if err != nil || u == nil {
		writeJSON(w, http.StatusNotFound, errResp(1001, "user not found"))
		return
	}
	var req struct {
		PlanName      string   `json:"plan_name"`
		DurationMonth int32    `json:"duration_months"`
		LimitBytes    int64    `json:"limit_bytes"`
		AssignedNodes []string `json:"assigned_nodes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.PlanName == "" {
		req.PlanName = "独立自定义订阅"
	}
	if req.DurationMonth <= 0 {
		req.DurationMonth = 1
	}
	if req.LimitBytes <= 0 {
		req.LimitBytes = 100 * 1024 * 1024 * 1024
	}

	now := time.Now()
	exp := now.AddDate(0, int(req.DurationMonth), 0)
	slug := GenerateSubscriptionSlug(u.Username)
	subID := fmt.Sprintf("sub_%s", slug)

	sub := &Subscription{
		SubID:         subID,
		UserID:        u.ID,
		UserUUID:      u.UUID,
		SubSlug:       slug,
		SubToken:      GenerateUserToken(),
		SubTicketSeed: GenerateTicketSeed(),
		PlanName:      req.PlanName,
		AssignedNodes: req.AssignedNodes,
		LimitBytes:    req.LimitBytes,
		UsedBytes:     0,
		ExpireAt:      exp,
		SwitchStatus:  "on",
		Status:        true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := h.svc.store.CreateSubscription(sub); err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": 0, "data": sub})
}

func (h *UserHandler) SwitchSubscription(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("id")
	var req struct {
		SwitchStatus string `json:"switch_status"` // "on" or "off"
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.SwitchStatus != "on" && req.SwitchStatus != "off" {
		req.SwitchStatus = "off"
	}
	if err := h.svc.store.UpdateSubscriptionSwitch(subID, req.SwitchStatus); err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "switch updated", "switch_status": req.SwitchStatus})
}

func (h *UserHandler) DeleteSubscription(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("id")
	if err := h.svc.store.DeleteSubscription(subID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "subscription deleted"})
}

func (h *UserHandler) RenewSubscription(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("id")
	var req struct {
		PlanMonths int32 `json:"duration_months"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.PlanMonths <= 0 {
		req.PlanMonths = 1
	}
	sub, err := h.svc.store.RenewSubscription(subID, req.PlanMonths, 0, "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": sub})
}

// SeedAdmin ensures admin user and admin subscription exist.
func SeedAdmin(svc *UserService, db UserStore) {
	initPwd := os.Getenv("ADMIN_INIT_PASSWORD")
	if initPwd == "" {
		initPwd = "admin123456"
	}

	var adminUser *User
	existing, err := db.GetUserByUsername("admin")
	if err == nil && existing != nil {
		adminUser = existing
		if !existing.IsStaff {
			_ = db.SetStaff(existing.ID, true)
		}
		if existing.PasswordHash == "" || !CheckPassword(initPwd, existing.PasswordHash) {
			_ = db.SetPassword(existing.ID, HashPassword(initPwd))
		}
		if existing.SubSlug != "superadmin" {
			_ = db.UpdateSubSlug(existing.ID, "superadmin")
		}
	} else {
		u, err := svc.Register(CreateUserParams{
			Username: "admin", Password: initPwd, Email: "admin@vpn.local", IsStaff: true,
		})
		if err == nil && u != nil {
			adminUser = u
			_ = db.SetStaff(u.ID, true)
			_ = db.UpdateSubSlug(u.ID, "superadmin")
		}
	}

	if adminUser != nil {
		subs, _ := db.ListSubscriptions(adminUser.ID)
		if len(subs) == 0 {
			now := time.Now()
			exp := now.Add(10 * 365 * 24 * time.Hour)
			_ = db.CreateSubscription(&Subscription{
				SubID:         "sub_admin_" + GenerateShortUUID(),
				UserID:        adminUser.ID,
				UserUUID:      adminUser.UUID,
				SubSlug:       "superadmin",
				SubToken:      GenerateUserToken(),
				SubTicketSeed: GenerateTicketSeed(),
				PlanName:      "管理员专享订阅",
				AssignedNodes: []string{},
				LimitBytes:    10 * 1024 * 1024 * 1024 * 1024, // 10TB
				UsedBytes:     0,
				ExpireAt:      exp,
				SwitchStatus:  "on",
				Status:        true,
				CreatedAt:     now,
				UpdatedAt:     now,
			})
		}
	}
}
