// Package contextstore：AI 流断线续传上下文。
// 默认使用 MemoryStore（无磁盘）；SQLite 可选，不走热路径默认。
package contextstore

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// StreamContext AI 流上下文记录
type StreamContext struct {
	ContextID        string
	SessionID        string
	StreamID         uint32
	TargetHost       string
	TargetPort       uint32
	LastSequence     uint64
	BytesTransferred uint64
	ModelName        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Backend 统一接口（内存或 SQLite）
type Backend interface {
	Save(ctx StreamContext) error
	Get(contextID string) (*StreamContext, error)
	Delete(contextID string) error
	Cleanup(ttl time.Duration) (int, error)
	Count() int
	Close() error
}

// Store 兼容旧 API 的包装（默认委托 Backend）
type Store struct {
	Backend
}

// New 打开 SQLite 存储（可选，高负载场景优先 NewMemory）。
func New(dbPath string) (*Store, error) {
	if dbPath == "" {
		dbPath = "aero_context.db"
	}
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)

	s := &sqliteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	log.Printf("[ContextStore] SQLite: %s", dbPath)
	return &Store{Backend: s}, nil
}

// NewDefault 生产默认：内存，避免每连接写盘拖垮 VPS。
func NewDefault() *Store {
	return &Store{Backend: NewMemory(4096)}
}

type sqliteStore struct {
	db *sql.DB
	mu sync.RWMutex
}

func (s *sqliteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS stream_contexts (
			context_id       TEXT PRIMARY KEY,
			session_id       TEXT NOT NULL,
			stream_id        INTEGER NOT NULL,
			target_host      TEXT NOT NULL,
			target_port      INTEGER NOT NULL DEFAULT 443,
			last_sequence    INTEGER NOT NULL DEFAULT 0,
			bytes_transferred INTEGER NOT NULL DEFAULT 0,
			model_name       TEXT NOT NULL DEFAULT '',
			created_at       INTEGER NOT NULL,
			updated_at       INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_session ON stream_contexts(session_id);
		CREATE INDEX IF NOT EXISTS idx_updated ON stream_contexts(updated_at);
	`)
	return err
}

func (s *sqliteStore) Save(ctx StreamContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	if ctx.CreatedAt.IsZero() {
		ctx.CreatedAt = time.Now()
	}
	ctx.UpdatedAt = time.Now()
	_, err := s.db.Exec(`
		INSERT INTO stream_contexts
			(context_id, session_id, stream_id, target_host, target_port,
			 last_sequence, bytes_transferred, model_name, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(context_id) DO UPDATE SET
			session_id=excluded.session_id,
			last_sequence=excluded.last_sequence,
			bytes_transferred=excluded.bytes_transferred,
			updated_at=excluded.updated_at
	`, ctx.ContextID, ctx.SessionID, ctx.StreamID, ctx.TargetHost, ctx.TargetPort,
		ctx.LastSequence, ctx.BytesTransferred, ctx.ModelName, ctx.CreatedAt.Unix(), now)
	if err != nil {
		return fmt.Errorf("save: %w", err)
	}
	return nil
}

func (s *sqliteStore) Get(contextID string) (*StreamContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	row := s.db.QueryRow(`
		SELECT context_id, session_id, stream_id, target_host, target_port,
		       last_sequence, bytes_transferred, model_name, created_at, updated_at
		FROM stream_contexts WHERE context_id = ?
	`, contextID)
	var ctx StreamContext
	var createdAt, updatedAt int64
	err := row.Scan(&ctx.ContextID, &ctx.SessionID, &ctx.StreamID,
		&ctx.TargetHost, &ctx.TargetPort, &ctx.LastSequence,
		&ctx.BytesTransferred, &ctx.ModelName, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	ctx.CreatedAt = time.Unix(createdAt, 0)
	ctx.UpdatedAt = time.Unix(updatedAt, 0)
	return &ctx, nil
}

func (s *sqliteStore) Delete(contextID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM stream_contexts WHERE context_id = ?", contextID)
	return err
}

func (s *sqliteStore) Cleanup(ttl time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-ttl).Unix()
	result, err := s.db.Exec("DELETE FROM stream_contexts WHERE updated_at < ?", cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

func (s *sqliteStore) Count() int {
	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM stream_contexts").Scan(&count)
	return count
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}
