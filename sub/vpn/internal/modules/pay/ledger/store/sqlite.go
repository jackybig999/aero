// Package store defines the data access interface for payment-ledger.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/domain"
	_ "modernc.org/sqlite"
)

// SQLiteStore 提供基于 SQLite 的原子事务记账持久化实现。
// 纯 Go 驱动编译（无 CGO），支持崩溃安全与 ACID 事务。
type SQLiteStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// NewSQLiteStore 初始化 SQLite 账本，并在不存在时自动建立表结构与索引。
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if dbPath == "" {
		dbPath = filepath.Join("data", "ledger.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("ledger dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS ledger_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ledger_no TEXT UNIQUE NOT NULL,
		user_id INTEGER NOT NULL,
		amount_cents INTEGER NOT NULL,
		direction TEXT NOT NULL,
		channel TEXT NOT NULL,
		channel_ref TEXT,
		settled INTEGER NOT NULL DEFAULT 0,
		settled_at TEXT,
		settlement_no TEXT,
		created_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ledger_direction_settled ON ledger_entries(direction, settled);
	CREATE INDEX IF NOT EXISTS idx_ledger_created_at ON ledger_entries(created_at);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init ledger schema: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// Close 关闭数据库连接
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Append 采用原子事务写入单笔记账流水
func (s *SQLiteStore) Append(e *domain.Entry) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	createdAt := e.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	var settledInt int
	if e.Settled {
		settledInt = 1
	}

	var settledAtStr sql.NullString
	if e.SettledAt != nil {
		settledAtStr = sql.NullString{String: e.SettledAt.Format(time.RFC3339), Valid: true}
	}

	query := `
	INSERT INTO ledger_entries (
		ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	res, err := tx.Exec(
		query,
		e.LedgerNo, e.UserID, e.AmountCents, e.Direction, e.Channel, e.ChannelRef,
		settledInt, settledAtStr, e.SettlementNo, createdAt.Format(time.RFC3339),
	)
	if err != nil {
		return 0, fmt.Errorf("insert ledger entry: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}

	e.ID = uint64(id)
	e.CreatedAt = createdAt
	return e.ID, nil
}

// GetByLedgerNo 根据唯一凭单号查询账本条目
func (s *SQLiteStore) GetByLedgerNo(no string) (*domain.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at
	FROM ledger_entries WHERE ledger_no = ?;
	`
	var e domain.Entry
	var settledInt int
	var settledAtStr, channelRef, settlementNo sql.NullString
	var createdAtStr string

	err := s.db.QueryRow(query, no).Scan(
		&e.ID, &e.LedgerNo, &e.UserID, &e.AmountCents, &e.Direction, &e.Channel,
		&channelRef, &settledInt, &settledAtStr, &settlementNo, &createdAtStr,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query by ledger_no: %w", err)
	}

	e.Settled = (settledInt == 1)
	if channelRef.Valid {
		e.ChannelRef = channelRef.String
	}
	if settlementNo.Valid {
		e.SettlementNo = settlementNo.String
	}
	if settledAtStr.Valid {
		if t, err := time.Parse(time.RFC3339, settledAtStr.String); err == nil {
			e.SettledAt = &t
		}
	}
	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		e.CreatedAt = t
	}

	return &e, nil
}

// ListAll 查询全量流水账目
func (s *SQLiteStore) ListAll() ([]domain.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at
	FROM ledger_entries ORDER BY id ASC;
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query all entries: %w", err)
	}
	defer rows.Close()

	var entries []domain.Entry
	for rows.Next() {
		var e domain.Entry
		var settledInt int
		var settledAtStr, channelRef, settlementNo sql.NullString
		var createdAtStr string

		if err := rows.Scan(
			&e.ID, &e.LedgerNo, &e.UserID, &e.AmountCents, &e.Direction, &e.Channel,
			&channelRef, &settledInt, &settledAtStr, &settlementNo, &createdAtStr,
		); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}

		e.Settled = (settledInt == 1)
		if channelRef.Valid {
			e.ChannelRef = channelRef.String
		}
		if settlementNo.Valid {
			e.SettlementNo = settlementNo.String
		}
		if settledAtStr.Valid {
			if t, err := time.Parse(time.RFC3339, settledAtStr.String); err == nil {
				e.SettledAt = &t
			}
		}
		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			e.CreatedAt = t
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ListUnsettled 查询指定流向且未清算的账目列表
func (s *SQLiteStore) ListUnsettled(direction string) ([]domain.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var query string
	var args []any
	if direction != "" {
		query = `
		SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at
		FROM ledger_entries WHERE settled = 0 AND direction = ? ORDER BY id ASC;
		`
		args = append(args, direction)
	} else {
		query = `
		SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at
		FROM ledger_entries WHERE settled = 0 ORDER BY id ASC;
		`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query unsettled: %w", err)
	}
	defer rows.Close()

	var entries []domain.Entry
	for rows.Next() {
		var e domain.Entry
		var settledInt int
		var settledAtStr, channelRef, settlementNo sql.NullString
		var createdAtStr string

		if err := rows.Scan(
			&e.ID, &e.LedgerNo, &e.UserID, &e.AmountCents, &e.Direction, &e.Channel,
			&channelRef, &settledInt, &settledAtStr, &settlementNo, &createdAtStr,
		); err != nil {
			return nil, fmt.Errorf("scan unsettled entry: %w", err)
		}

		e.Settled = (settledInt == 1)
		if channelRef.Valid {
			e.ChannelRef = channelRef.String
		}
		if settlementNo.Valid {
			e.SettlementNo = settlementNo.String
		}
		if settledAtStr.Valid {
			if t, err := time.Parse(time.RFC3339, settledAtStr.String); err == nil {
				e.SettledAt = &t
			}
		}
		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			e.CreatedAt = t
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// MarkSettled 标记账单已完成结算
func (s *SQLiteStore) MarkSettled(ledgerNo, settlementNo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	nowStr := time.Now().Format(time.RFC3339)
	res, err := tx.Exec(
		`UPDATE ledger_entries SET settled = 1, settled_at = ?, settlement_no = ? WHERE ledger_no = ?;`,
		nowStr, settlementNo, ledgerNo,
	)
	if err != nil {
		return fmt.Errorf("update settled: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// GetDailySummary 汇总指定日期的财务流水
func (s *SQLiteStore) GetDailySummary(date time.Time) (*domain.Summary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	datePrefix := date.Format("2006-01-02")
	query := `
	SELECT
		COALESCE(SUM(CASE WHEN direction = 'IN' THEN amount_cents ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN direction = 'OUT' THEN amount_cents ELSE 0 END), 0),
		COUNT(*)
	FROM ledger_entries
	WHERE created_at LIKE ?;
	`
	var sum domain.Summary
	sum.Date = datePrefix
	err := s.db.QueryRow(query, datePrefix+"%").Scan(
		&sum.TotalInCents, &sum.TotalOutCents, &sum.EntryCount,
	)
	if err != nil {
		return nil, fmt.Errorf("query daily summary: %w", err)
	}
	return &sum, nil
}
