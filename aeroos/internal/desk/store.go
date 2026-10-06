package desk

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	globalDB *sql.DB
	dbMutex  sync.RWMutex

	ErrUserExists      = errors.New("用户已存在")
	ErrUserNotFound    = errors.New("用户不存在")
	ErrInvalidPassword = errors.New("密码错误")
	ErrInvalidToken    = errors.New("无效或过期的登录凭据")

	tokenStore = make(map[string]userSession)
	tokenMutex sync.RWMutex
)

// Profile 指纹浏览器运行环境模型
type Profile struct {
	ID                int64      `json:"id"`
	UserID            int64      `json:"user_id"`
	Name              string     `json:"name"`
	Notes             string     `json:"notes"`
	IconColor         string     `json:"icon_color"`
	KernelType        string     `json:"kernel_type"`
	KernelVersion     string     `json:"kernel_version"`
	ProxyID           int64      `json:"proxy_id"`
	FingerprintConfig string     `json:"fingerprint_config"`
	DataDir           string     `json:"data_dir"`
	Status            string     `json:"status"` // "stopped", "running", "error"
	LastLaunchedAt    *time.Time `json:"last_launched_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

// ProxyItem 代理池条目
type ProxyItem struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	RawInput  string    `json:"raw_input"`
	Protocol  string    `json:"protocol"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// User 用户模型
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

// ProfileExportDTO 环境导出数据结构
type ProfileExportDTO struct {
	Version           string             `json:"version"`
	ExportedAt        time.Time          `json:"exported_at"`
	Name              string             `json:"name"`
	Notes             string             `json:"notes"`
	KernelType        string             `json:"kernel_type"`
	KernelVersion     string             `json:"kernel_version"`
	ProxyProtocol     string             `json:"proxy_protocol,omitempty"`
	ProxyHost         string             `json:"proxy_host,omitempty"`
	ProxyPort         int                `json:"proxy_port,omitempty"`
	FingerprintConfig *FingerprintConfig `json:"fingerprint_config"`
}

// InitDB 初始化单文件 SQLite 数据库并执行 Schema 自动迁移
func InitDB(dbPath string) (*sql.DB, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if globalDB != nil {
		return globalDB, nil
	}

	if dbPath == "" {
		dbPath = "data.db"
	}

	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("创建数据库目录失败: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 数据库失败: %w", err)
	}

	_, _ = db.Exec("PRAGMA journal_mode = WAL;")
	_, _ = db.Exec("PRAGMA busy_timeout = 5000;")
	_, _ = db.Exec("PRAGMA synchronous = NORMAL;")

	// 生产级单写者架构与无锁资源回收：单机 Pure-Go SQLite 数据库强制初始化 SetMaxOpenConns(1) 彻底消灭锁库 (PROJECT_RULES.md P18)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := migrateSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("数据库表迁移失败: %w", err)
	}

	globalDB = db
	return globalDB, nil
}

// GetDB 获取全局数据库句柄
func GetDB() *sql.DB {
	dbMutex.RLock()
	defer dbMutex.RUnlock()
	return globalDB
}

// CloseDB 关闭全局数据库连接
func CloseDB() error {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if globalDB != nil {
		err := globalDB.Close()
		globalDB = nil
		return err
	}
	return nil
}

func migrateSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		salt TEXT NOT NULL,
		email TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS proxies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		raw_input TEXT NOT NULL,
		protocol TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		username TEXT,
		password TEXT,
		status TEXT DEFAULT 'ready',
		outbound_ip TEXT,
		latency_ms INTEGER DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS profiles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		notes TEXT,
		icon_color TEXT DEFAULT '#3B82F6',
		kernel_type TEXT DEFAULT 'chrome',
		kernel_version TEXT DEFAULT '133',
		proxy_id INTEGER DEFAULT 0,
		fingerprint_config TEXT NOT NULL,
		data_dir TEXT NOT NULL,
		status TEXT DEFAULT 'stopped',
		last_launched_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS app_session (
		key TEXT PRIMARY KEY,
		val TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := db.Exec(schema)
	return err
}

// EncryptField encrypts a sensitive string using AES-256-GCM.
func EncryptField(plain, secret string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if secret == "" {
		secret = "aero-finger-default-secret-salt"
	}
	h := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return hex.EncodeToString(sealed), nil
}

// DecryptField decrypts an AES-256-GCM encrypted hex string.
func DecryptField(cipherHex, secret string) (string, error) {
	if cipherHex == "" {
		return "", nil
	}
	data, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}
	if secret == "" {
		secret = "aero-finger-default-secret-salt"
	}
	h := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// BackupUserData 将指定 profile 的 UserData 打包为 zip 备份
func BackupUserData(userDataDir, destBackupZip string) error {
	if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
		return fmt.Errorf("UserData 目录不存在: %s", userDataDir)
	}

	if destBackupZip == "" {
		timestamp := time.Now().Format("20060102_150405")
		destBackupZip = filepath.Join(filepath.Dir(userDataDir), fmt.Sprintf("backup_%s.zip", timestamp))
	}

	dir := filepath.Dir(destBackupZip)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	out, err := os.Create(destBackupZip)
	if err != nil {
		return fmt.Errorf("创建备份文件失败: %w", err)
	}
	defer out.Close()

	w := zip.NewWriter(out)
	defer w.Close()

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name := info.Name()
		if name == "SingletonLock" || name == "SingletonSocket" || name == "parent.lock" || strings.HasSuffix(name, ".lock") {
			return nil
		}

		relPath, err := filepath.Rel(userDataDir, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		zipEntryPath := filepath.ToSlash(relPath)
		if info.IsDir() {
			zipEntryPath += "/"
			_, err := w.Create(zipEntryPath)
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = zipEntryPath
		header.Method = zip.Deflate

		writer, err := w.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	}

	return filepath.Walk(userDataDir, walker)
}

// RestoreUserData 从备份 zip 还原到指定的 profile 目录
func RestoreUserData(backupZip, destUserDataDir string) error {
	r, err := zip.OpenReader(backupZip)
	if err != nil {
		return fmt.Errorf("打开备份文件失败: %w", err)
	}
	defer r.Close()

	if err := os.MkdirAll(destUserDataDir, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %w", err)
	}

	for _, f := range r.File {
		fpath := filepath.Join(destUserDataDir, filepath.FromSlash(f.Name))
		if !strings.HasPrefix(fpath, filepath.Clean(destUserDataDir)+string(os.PathSeparator)) {
			return fmt.Errorf("非法路径穿越: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return fmt.Errorf("创建子目录失败: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// ExportProfileConfig 将环境指纹配置导出为 JSON 文件
func ExportProfileConfig(profile *Profile, proxyCfg *ProxyConfig, fp *FingerprintConfig, exportPath string) error {
	dto := ProfileExportDTO{
		Version:           "2.0",
		ExportedAt:        time.Now(),
		Name:              profile.Name,
		Notes:             profile.Notes,
		KernelType:        profile.KernelType,
		KernelVersion:     profile.KernelVersion,
		FingerprintConfig: fp,
	}

	if proxyCfg != nil && proxyCfg.Enabled {
		dto.ProxyProtocol = proxyCfg.Protocol
		dto.ProxyHost = proxyCfg.Host
		dto.ProxyPort = proxyCfg.Port
	}

	data, err := json.MarshalIndent(dto, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	dir := filepath.Dir(exportPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(exportPath, data, 0644)
}

// ImportProfileConfig 从导出的 JSON 文件导入指纹环境配置
func ImportProfileConfig(importPath string) (*ProfileExportDTO, error) {
	data, err := os.ReadFile(importPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var dto ProfileExportDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	return &dto, nil
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

// RegisterUserWithEmail 按照通用规范注册用户
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

// RegisterUser 注册新用户
func RegisterUser(db *sql.DB, username, password string) (*User, error) {
	return RegisterUserWithEmail(db, username, "", password)
}

// CountUsers 获取系统中已注册的用户总数
func CountUsers(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT count(*) FROM users").Scan(&count)
	return count, err
}

// AuthenticateUser 验证用户身份并签发会话 Token
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
