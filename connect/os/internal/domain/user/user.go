package user

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrUserExists      = errors.New("用户已存在")
	ErrUserNotFound    = errors.New("用户不存在")
	ErrInvalidPassword = errors.New("密码错误")
	ErrInvalidToken    = errors.New("无效或过期的登录凭据")

	tokenStore = make(map[string]userSession)
	tokenMutex sync.RWMutex
)

type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type userSession struct {
	UserID    int64
	Username  string
	ExpiresAt time.Time
}

func hashPassword(password, salt string) string {
	hasher := sha256.New()
	hasher.Write([]byte(salt + password + "fingerprint_salt_v2"))
	return hex.EncodeToString(hasher.Sum(nil))
}

func generateSalt() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateToken() string {
	bytes := make([]byte, 24)
	_, _ = rand.Read(bytes)
	return "tok_" + hex.EncodeToString(bytes)
}

// RegisterUserWithEmail 按照通用规范注册用户 (支持邮箱/手机及密码长度校验)
func RegisterUserWithEmail(db *sql.DB, username, email, password string) (*User, error) {
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	if username == "" || password == "" {
		return nil, errors.New("用户名与登录密码为必填项")
	}
	if len(username) < 3 {
		return nil, errors.New("用户名长度至少为 3 个字符")
	}
	if len(password) < 6 {
		return nil, errors.New("登录密码长度至少为 6 个字符")
	}

	salt := generateSalt()
	passwordHash := hashPassword(password, salt)

	res, err := db.Exec("INSERT INTO users (username, password_hash, salt, email) VALUES (?, ?, ?, ?)", username, passwordHash, salt, email)
	if err != nil {
		return nil, ErrUserExists
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("获取新增用户ID失败: %w", err)
	}

	return &User{
		ID:        id,
		Username:  username,
		Email:     email,
		CreatedAt: time.Now(),
	}, nil
}

// RegisterUser 注册新用户 (兼容旧签名)
func RegisterUser(db *sql.DB, username, password string) (*User, error) {
	return RegisterUserWithEmail(db, username, "", password)
}

// CountUsers 获取系统中已注册的用户总数
func CountUsers(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT count(*) FROM users").Scan(&count)
	return count, err
}

// AuthenticateUser 验证用户身份并签发会话 Token (支持用户名或邮箱)
func AuthenticateUser(db *sql.DB, usernameOrEmail, password string) (*User, string, error) {
	var user User
	var passwordHash, salt string

	row := db.QueryRow("SELECT id, username, password_hash, salt, email, created_at FROM users WHERE username = ? OR (email != '' AND email = ?)", usernameOrEmail, usernameOrEmail)
	err := row.Scan(&user.ID, &user.Username, &passwordHash, &salt, &user.Email, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrUserNotFound
	} else if err != nil {
		return nil, "", fmt.Errorf("查询用户失败: %w", err)
	}

	expectedHash := hashPassword(password, salt)
	if expectedHash != passwordHash {
		return nil, "", ErrInvalidPassword
	}

	token := generateToken()
	tokenMutex.Lock()
	tokenStore[token] = userSession{
		UserID:    user.ID,
		Username:  user.Username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	tokenMutex.Unlock()

	return &user, token, nil
}

// Logout 注销用户会话
func Logout(token string) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	delete(tokenStore, token)
}

// ValidateToken 校验登录 Token 并主动清理过期会话
func ValidateToken(token string) (*User, error) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	session, exists := tokenStore[token]
	if !exists || time.Now().After(session.ExpiresAt) {
		delete(tokenStore, token)
		return nil, ErrInvalidToken
	}

	return &User{
		ID:       session.UserID,
		Username: session.Username,
	}, nil
}

// SaveSessionUser 持久化保存当前活跃登录用户会话
func SaveSessionUser(db *sql.DB, userID int64) error {
	if db == nil {
		return errors.New("数据库未初始化")
	}
	_, err := db.Exec(`INSERT INTO app_session (key, val, updated_at) VALUES ('current_user_id', ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET val = excluded.val, updated_at = CURRENT_TIMESTAMP`, fmt.Sprintf("%d", userID))
	return err
}

// GetSavedSessionUser 获取持久化保存的活跃登录用户
func GetSavedSessionUser(db *sql.DB) (*User, error) {
	if db == nil {
		return nil, errors.New("数据库未初始化")
	}
	var val string
	err := db.QueryRow(`SELECT val FROM app_session WHERE key = 'current_user_id'`).Scan(&val)
	if err != nil {
		return nil, err
	}
	var user User
	err = db.QueryRow(`SELECT id, username, email, created_at FROM users WHERE id = ?`, val).Scan(
		&user.ID, &user.Username, &user.Email, &user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ClearSessionUser 清除持久化的活跃会话
func ClearSessionUser(db *sql.DB) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(`DELETE FROM app_session WHERE key = 'current_user_id'`)
	return err
}
