package edge

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动（已在 go.mod）
)

// edge 本地用户库（ADR-0010）：只保存本节点用户（iss=edge），字段语义与中台 subscription 对齐。
// 连接参数按 PROJECT_RULES §6.10：WAL、单写连接 + 读连接池、busy_timeout、外键，均写入 DSN。

const (
	UserActive   = "active"
	UserDisabled = "disabled"

	userStoreSchemaVersion = 1
	userStoreReadConns     = 4
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")

	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_@.-]{2,64}$`)
	slugPattern     = regexp.MustCompile(`^[A-Za-z0-9_@.-]{4,96}$`)
)

// LocalUser 是本地用户；对应中台 subscription：UID↔user_uuid、Slug↔sub_slug、
// Tier↔plan_name、QuotaBytes↔limit_bytes、UsedBytes↔used_bytes。
type LocalUser struct {
	UID        string
	Username   string
	Slug       string
	Tier       string
	Classes    []string
	MaxDevices int
	QuotaBytes int64 // 0 = 不限
	UsedBytes  int64
	BWBps      int64 // 0 = 不限
	ExpireAt   int64 // Unix 秒；0 = 不限期
	Status     string
	CreatedAt  int64
	UpdatedAt  int64
}

// UserStore 管理本地用户。写操作经单一写连接串行化，读操作使用读连接池。
type UserStore struct {
	write *sql.DB
	read  *sql.DB
}

// OpenUserStore 打开（或创建）path 处的数据库并执行迁移。
func OpenUserStore(path string) (*UserStore, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	write, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open user store: %w", err)
	}
	write.SetMaxOpenConns(1)
	if err := migrateUserStore(write); err != nil {
		_ = write.Close()
		return nil, err
	}
	read, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = write.Close()
		return nil, fmt.Errorf("open user store (read): %w", err)
	}
	read.SetMaxOpenConns(userStoreReadConns)
	return &UserStore{write: write, read: read}, nil
}

func migrateUserStore(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > userStoreSchemaVersion {
		return fmt.Errorf("user store schema %d is newer than supported %d", version, userStoreSchemaVersion)
	}
	if version == userStoreSchemaVersion {
		return nil
	}
	// v0 → v1
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS local_user (
	uid         TEXT PRIMARY KEY,
	username    TEXT NOT NULL UNIQUE,
	slug        TEXT NOT NULL UNIQUE,
	tier        TEXT NOT NULL,
	classes     TEXT NOT NULL,
	max_devices INTEGER NOT NULL CHECK (max_devices BETWEEN 1 AND 64),
	quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK (quota_bytes >= 0),
	used_bytes  INTEGER NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
	bw_bps      INTEGER NOT NULL DEFAULT 0 CHECK (bw_bps >= 0),
	expire_at   INTEGER NOT NULL DEFAULT 0,
	status      TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL
);
PRAGMA user_version = 1;`)
	if err != nil {
		return fmt.Errorf("migrate user store to v1: %w", err)
	}
	return nil
}

// Close 关闭两个连接池。
func (s *UserStore) Close() error {
	return errors.Join(s.read.Close(), s.write.Close())
}

func validateLocalUser(u LocalUser) error {
	switch {
	case u.UID == "" || !uidPattern.MatchString(u.UID):
		return errors.New("invalid uid")
	case !usernamePattern.MatchString(u.Username):
		return errors.New("invalid username")
	case !slugPattern.MatchString(u.Slug):
		return errors.New("invalid slug")
	case !tierPattern.MatchString(u.Tier):
		return errors.New("invalid tier")
	case u.MaxDevices < 1 || u.MaxDevices > 64:
		return errors.New("max_devices must be 1..64")
	case u.QuotaBytes < 0 || u.UsedBytes < 0 || u.BWBps < 0 || u.ExpireAt < 0:
		return errors.New("negative limit")
	case u.Status != UserActive && u.Status != UserDisabled:
		return errors.New("invalid status")
	}
	return validateClasses(u.Classes)
}

func validateClasses(classes []string) error {
	if len(classes) == 0 {
		return errors.New("at least one traffic class is required")
	}
	seen := make(map[string]bool, len(classes))
	for _, c := range classes {
		if !knownClass[c] || seen[c] {
			return fmt.Errorf("invalid traffic class %q", c)
		}
		seen[c] = true
	}
	return nil
}

// Create 新增用户；uid、username 或 slug 重复时返回 ErrUserExists。
func (s *UserStore) Create(u LocalUser) error {
	if err := validateLocalUser(u); err != nil {
		return err
	}
	classes, err := json.Marshal(u.Classes)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = s.write.Exec(`INSERT INTO local_user
		(uid, username, slug, tier, classes, max_devices, quota_bytes, used_bytes, bw_bps, expire_at, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.UID, u.Username, u.Slug, u.Tier, string(classes), u.MaxDevices, u.QuotaBytes, u.UsedBytes, u.BWBps,
		u.ExpireAt, u.Status, now, now)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrUserExists
	}
	return err
}

const localUserColumns = `uid, username, slug, tier, classes, max_devices, quota_bytes, used_bytes, bw_bps, expire_at, status, created_at, updated_at`

func scanLocalUser(row interface{ Scan(...any) error }) (LocalUser, error) {
	var u LocalUser
	var classes string
	err := row.Scan(&u.UID, &u.Username, &u.Slug, &u.Tier, &classes, &u.MaxDevices, &u.QuotaBytes,
		&u.UsedBytes, &u.BWBps, &u.ExpireAt, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return LocalUser{}, err
	}
	if err := json.Unmarshal([]byte(classes), &u.Classes); err != nil {
		return LocalUser{}, fmt.Errorf("decode classes of %s: %w", u.UID, err)
	}
	return u, nil
}

func (s *UserStore) getBy(column, value string) (LocalUser, bool, error) {
	u, err := scanLocalUser(s.read.QueryRow(`SELECT `+localUserColumns+` FROM local_user WHERE `+column+` = ?`, value))
	if errors.Is(err, sql.ErrNoRows) {
		return LocalUser{}, false, nil
	}
	return u, err == nil, err
}

// Get 按订阅 slug 查询。
func (s *UserStore) Get(slug string) (LocalUser, bool, error) { return s.getBy("slug", slug) }

// GetByUID 按 uid 查询。
func (s *UserStore) GetByUID(uid string) (LocalUser, bool, error) { return s.getBy("uid", uid) }

// List 返回全部本地用户（按创建时间）。
func (s *UserStore) List() ([]LocalUser, error) {
	rows, err := s.read.Query(`SELECT ` + localUserColumns + ` FROM local_user ORDER BY created_at, uid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LocalUser
	for rows.Next() {
		u, err := scanLocalUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Delete 按 slug 删除；不存在时返回 ErrUserNotFound。
func (s *UserStore) Delete(slug string) error {
	res, err := s.write.Exec(`DELETE FROM local_user WHERE slug = ?`, slug)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// AddUsage 原子累加用量（单条 UPDATE，L0 §7.5）；uid 不存在时返回 ErrUserNotFound。
func (s *UserStore) AddUsage(uid string, bytes int64) error {
	if bytes < 0 {
		return errors.New("negative usage")
	}
	res, err := s.write.Exec(`UPDATE local_user SET used_bytes = used_bytes + ?, updated_at = ? WHERE uid = ?`,
		bytes, time.Now().Unix(), uid)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrUserNotFound
	}
	return nil
}
