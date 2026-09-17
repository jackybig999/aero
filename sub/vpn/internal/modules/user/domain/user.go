// Package domain defines core types for user-center.
package domain

import "time"

// User represents a registered user.
type User struct {
	ID          uint64    `json:"id"`
	Username    string    `json:"username"`
	PasswordHash string   `json:"-"`
	Email       string    `json:"email,omitempty"`
	Status      bool      `json:"status"`
	IsStaff     bool      `json:"is_staff"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	Username string
	Password string
	Email    string
	IsStaff  bool // true = 管理员；false = 订阅用户
}
