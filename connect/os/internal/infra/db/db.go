package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	globalDB *sql.DB
	dbMutex  sync.RWMutex
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

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

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
