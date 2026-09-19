// Package domain defines core types for user-center.
package domain

import "time"

// User represents a registered user.
type User struct {
	ID           uint64    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash,omitempty"`
	Phone        string    `json:"phone,omitempty"`
	Email        string    `json:"email,omitempty"`
	Status       bool      `json:"status"`
	IsStaff      bool      `json:"is_staff"`
	PlanName     string    `json:"plan_name,omitempty"`     // 订阅套餐: 月度套餐 / 季度套餐 / 年度套餐
	PlanMonths   int32     `json:"plan_months,omitempty"`   // 套餐月数: 1 / 3 / 12
	PriceCents   int64     `json:"price_cents,omitempty"`   // 套餐金额(分): 如 999 = $9.99
	SubSlug      string    `json:"sub_slug,omitempty"`      // 专属订阅 Slug: {username}{6位随机码}
	SubToken     string    `json:"sub_token,omitempty"`     // 专属连接凭证
	ExpireAt     time.Time `json:"expire_at,omitempty"`     // 订阅到期时间
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Sanitize 返回抹除敏感密码哈希后的用户安全副本，供外部 HTTP 接口返回
func (u *User) Sanitize() *User {
	if u == nil {
		return nil
	}
	cp := *u
	cp.PasswordHash = ""
	return &cp
}

// Plan represents a subscription plan.
type Plan struct {
	ID             int32     `json:"id"`
	Name           string    `json:"name"`
	DurationMonths int32     `json:"duration_months"`
	TrafficBytes   int64     `json:"traffic_bytes"`
	PriceCents     int64     `json:"price_cents"`
	Status         bool      `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

// TrafficStats holds user bandwidth data.
type TrafficStats struct {
	UserID     uint64     `json:"user_id"`
	UsedBytes  int64      `json:"used_bytes"`
	LimitBytes int64      `json:"limit_bytes"`
	ResetDate  *time.Time `json:"reset_date,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// CreateUserParams contains fields for user registration.
type CreateUserParams struct {
	Username   string
	Password   string
	Phone      string
	Email      string
	PlanName   string
	PlanMonths int32
	PriceCents int64
	IsStaff    bool // true = 管理员；false = 订阅用户
}
