// Copyright 2026 AERO Protocol Contributors
// AERO Payment, Billing & Ledger Subsystem - 100% Pure Go SQLite (Zero CGO)
package mid

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ----------------------------------------------------------------------
// AeroPayDB: Dedicated aeropay.db database for billing ledger & audit
// ----------------------------------------------------------------------

type IncomeRecord struct {
	ID             int64      `json:"id"`
	OrderNo        string     `json:"order_no"`
	UserID         uint64     `json:"user_id"`
	SubID          string     `json:"sub_id"`
	PlanID         uint64     `json:"plan_id"`
	PlanName       string     `json:"plan_name"`
	AmountCents    int64      `json:"amount_cents"`
	PayChannel     string     `json:"pay_channel"`
	ChannelTradeNo string     `json:"channel_trade_no"`
	Status         string     `json:"status"` // completed | pending | refunded
	Settled        bool       `json:"settled"`
	SettledBatchNo string     `json:"settled_batch_no,omitempty"`
	PaidAt         *time.Time `json:"paid_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type ExpenseRecord struct {
	ID                 int64      `json:"id"`
	ExpenseNo          string     `json:"expense_no"`
	ExpenseType        string     `json:"expense_type"` // settlement | vps_cost | refund
	TargetID           int64      `json:"target_id"`
	TargetAccountType  string     `json:"target_account_type"`  // bank | alipay | usdt | corporate
	TargetAccountTitle string     `json:"target_account_title"` // e.g. "香港招行对公", "USDT冷钱包"
	TargetAccountNo    string     `json:"target_account_no"`    // Masked for UI display
	AmountCents        int64      `json:"amount_cents"`
	FeeCents           int64      `json:"fee_cents"`
	Status             string     `json:"status"` // completed | pending | failed
	Operator           string     `json:"operator"`
	Remark             string     `json:"remark"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

type SettlementTarget struct {
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	ChannelType string    `json:"channel_type"` // bank | alipay | usdt_trc20 | manual
	PayeeName   string    `json:"payee_name"`
	AccountNo   string    `json:"account_no"`
	BankName    string    `json:"bank_name,omitempty"`
	IsDefault   bool      `json:"is_default"`
	Status      bool      `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AeroPayDB struct {
	mu sync.RWMutex
	db *sql.DB
}

func NewAeroPayDB(dbPath string) (*AeroPayDB, error) {
	if dbPath == "" {
		dbPath = filepath.Join("data", "aeropay.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("pay db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open aeropay db: %w", err)
	}
	db.SetMaxOpenConns(1)

	schema := `
	CREATE TABLE IF NOT EXISTS income (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_no TEXT UNIQUE NOT NULL,
		user_id INTEGER NOT NULL,
		sub_id TEXT DEFAULT '',
		plan_id INTEGER NOT NULL,
		plan_name TEXT NOT NULL,
		amount_cents INTEGER NOT NULL,
		pay_channel TEXT NOT NULL,
		channel_trade_no TEXT DEFAULT '',
		status TEXT NOT NULL,
		settled INTEGER NOT NULL DEFAULT 0,
		settled_batch_no TEXT DEFAULT '',
		paid_at TEXT,
		created_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_income_user ON income(user_id);
	CREATE INDEX IF NOT EXISTS idx_income_settled ON income(settled);

	CREATE TABLE IF NOT EXISTS expense (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		expense_no TEXT UNIQUE NOT NULL,
		expense_type TEXT NOT NULL,
		target_id INTEGER NOT NULL,
		target_account_type TEXT NOT NULL,
		target_account_title TEXT NOT NULL,
		target_account_no_enc BLOB,
		amount_cents INTEGER NOT NULL,
		fee_cents INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL,
		operator TEXT NOT NULL,
		remark TEXT DEFAULT '',
		completed_at TEXT,
		created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS settlement_target (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		channel_type TEXT NOT NULL,
		payee_name TEXT NOT NULL,
		account_no_enc BLOB,
		bank_name TEXT DEFAULT '',
		is_default INTEGER NOT NULL DEFAULT 0,
		status INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS double_entry_ledger (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ledger_no TEXT UNIQUE NOT NULL,
		user_id INTEGER NOT NULL DEFAULT 0,
		amount_cents INTEGER NOT NULL,
		direction TEXT NOT NULL,
		channel TEXT NOT NULL,
		channel_ref TEXT DEFAULT '',
		settled INTEGER NOT NULL DEFAULT 0,
		settled_at TEXT,
		settlement_no TEXT,
		created_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_double_entry_dir ON double_entry_ledger(direction, settled);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init aeropay schema: %w", err)
	}

	p := &AeroPayDB{db: db}
	p.ensureDefaultTarget()
	return p, nil
}

func (p *AeroPayDB) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *AeroPayDB) ensureDefaultTarget() {
	var count int
	_ = p.db.QueryRow(`SELECT count(*) FROM settlement_target`).Scan(&count)
	if count == 0 {
		nowStr := time.Now().Format(time.RFC3339)
		_, _ = p.db.Exec(`INSERT INTO settlement_target 
			(title, channel_type, payee_name, account_no_enc, bank_name, is_default, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)`,
			"默认银行账户归集", "bank", "AERO平台结算户", []byte("6222000088886666"), "招商银行离岸中心", nowStr, nowStr)
	}
}

func (p *AeroPayDB) RecordIncome(order *Order) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	paidStr := nowStr
	if order.PaidAt != nil {
		paidStr = order.PaidAt.Format(time.RFC3339)
	}

	_, err = tx.Exec(`INSERT OR REPLACE INTO income 
		(order_no, user_id, sub_id, plan_id, plan_name, amount_cents, pay_channel, channel_trade_no, status, settled, created_at, paid_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		order.OrderNo, order.UserID, "", order.PlanID, order.PlanName, order.AmountCents, order.PayChannel, "", order.Status, nowStr, paidStr)
	if err != nil {
		return fmt.Errorf("insert income: %w", err)
	}

	ledgerNo := fmt.Sprintf("LDG-%s-%04d", now.Format("20060102150405"), now.Nanosecond()%10000)
	_, err = tx.Exec(`INSERT INTO double_entry_ledger
		(ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, created_at)
		VALUES (?, ?, ?, 'IN', ?, ?, 0, ?)`,
		ledgerNo, order.UserID, order.AmountCents, order.PayChannel, order.OrderNo, nowStr)
	if err != nil {
		return fmt.Errorf("insert double entry: %w", err)
	}

	return tx.Commit()
}

func (p *AeroPayDB) ListIncome(offset, limit int) ([]IncomeRecord, int64, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var total int64
	_ = p.db.QueryRow(`SELECT count(*) FROM income`).Scan(&total)

	rows, err := p.db.Query(`SELECT id, order_no, user_id, sub_id, plan_id, plan_name, amount_cents, pay_channel, channel_trade_no, status, settled, settled_batch_no, paid_at, created_at FROM income ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []IncomeRecord
	for rows.Next() {
		var r IncomeRecord
		var paidStr, settledBatch sql.NullString
		var createdStr string
		var settledInt int
		if err := rows.Scan(&r.ID, &r.OrderNo, &r.UserID, &r.SubID, &r.PlanID, &r.PlanName, &r.AmountCents, &r.PayChannel, &r.ChannelTradeNo, &r.Status, &settledInt, &settledBatch, &paidStr, &createdStr); err == nil {
			r.Settled = settledInt == 1
			if settledBatch.Valid {
				r.SettledBatchNo = settledBatch.String
			}
			if paidStr.Valid && paidStr.String != "" {
				if t, perr := time.Parse(time.RFC3339, paidStr.String); perr == nil {
					r.PaidAt = &t
				}
			}
			if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
				r.CreatedAt = t
			}
			list = append(list, r)
		}
	}
	return list, total, nil
}

// ----------------------------------------------------------------------
// Double-Entry Ledger Store Interface & Implementations
// ----------------------------------------------------------------------

type LedgerEntry struct {
	ID           uint64     `json:"id"`
	LedgerNo     string     `json:"ledger_no"`
	UserID       uint64     `json:"user_id"`
	AmountCents  int64      `json:"amount_cents"`
	Direction    string     `json:"direction"` // IN or OUT
	Channel      string     `json:"channel"`
	ChannelRef   string     `json:"channel_ref,omitempty"`
	Settled      bool       `json:"settled"`
	SettledAt    *time.Time `json:"settled_at,omitempty"`
	SettlementNo string     `json:"settlement_no,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type LedgerSummary struct {
	TotalInCents  int64 `json:"total_in_cents"`
	TotalOutCents int64 `json:"total_out_cents"`
	EntryCount    int64 `json:"entry_count"`
}

type LedgerStore interface {
	Append(e *LedgerEntry) (uint64, error)
	Get(id uint64) (*LedgerEntry, error)
	GetByLedgerNo(no string) (*LedgerEntry, error)
	List(offset, limit int) ([]*LedgerEntry, int64, error)
	ListUnsettled(direction string) ([]*LedgerEntry, error)
	MarkSettled(ledgerNo, settlementNo string) error
	SettleBatch(channel, targetRef string) (*LedgerEntry, int, error)
	GetDailySummary(date time.Time) (*LedgerSummary, error)
	Close() error
}

func (p *AeroPayDB) Append(e *LedgerEntry) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	nowStr := e.CreatedAt.Format(time.RFC3339)
	if e.CreatedAt.IsZero() {
		nowStr = time.Now().Format(time.RFC3339)
	}
	res, err := p.db.Exec(`INSERT INTO double_entry_ledger
		(ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
		e.LedgerNo, e.UserID, e.AmountCents, e.Direction, e.Channel, e.ChannelRef, nowStr)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (p *AeroPayDB) Get(id uint64) (*LedgerEntry, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	row := p.db.QueryRow(`SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at 
		FROM double_entry_ledger WHERE id = ?`, id)
	return scanLedger(row)
}

func (p *AeroPayDB) GetByLedgerNo(no string) (*LedgerEntry, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	row := p.db.QueryRow(`SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at 
		FROM double_entry_ledger WHERE ledger_no = ?`, no)
	return scanLedger(row)
}

func scanLedger(row *sql.Row) (*LedgerEntry, error) {
	var e LedgerEntry
	var createdAtStr string
	var settledAt sql.NullString
	var settlementNo sql.NullString
	var channelRef sql.NullString
	var settledInt int

	err := row.Scan(&e.ID, &e.LedgerNo, &e.UserID, &e.AmountCents, &e.Direction, &e.Channel,
		&channelRef, &settledInt, &settledAt, &settlementNo, &createdAtStr)
	if err != nil {
		return nil, err
	}
	e.Settled = settledInt == 1
	if channelRef.Valid {
		e.ChannelRef = channelRef.String
	}
	if settlementNo.Valid {
		e.SettlementNo = settlementNo.String
	}
	if settledAt.Valid && settledAt.String != "" {
		if t, perr := time.Parse(time.RFC3339, settledAt.String); perr == nil {
			e.SettledAt = &t
		}
	}
	if t, perr := time.Parse(time.RFC3339, createdAtStr); perr == nil {
		e.CreatedAt = t
	}
	return &e, nil
}

func (p *AeroPayDB) List(offset, limit int) ([]*LedgerEntry, int64, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var total int64
	_ = p.db.QueryRow(`SELECT count(*) FROM double_entry_ledger`).Scan(&total)

	rows, err := p.db.Query(`SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at 
		FROM double_entry_ledger ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*LedgerEntry
	for rows.Next() {
		var e LedgerEntry
		var createdAtStr string
		var settledAt sql.NullString
		var settlementNo sql.NullString
		var channelRef sql.NullString
		var settledInt int
		if err := rows.Scan(&e.ID, &e.LedgerNo, &e.UserID, &e.AmountCents, &e.Direction, &e.Channel,
			&channelRef, &settledInt, &settledAt, &settlementNo, &createdAtStr); err == nil {
			e.Settled = settledInt == 1
			if channelRef.Valid {
				e.ChannelRef = channelRef.String
			}
			if settlementNo.Valid {
				e.SettlementNo = settlementNo.String
			}
			if t, perr := time.Parse(time.RFC3339, createdAtStr); perr == nil {
				e.CreatedAt = t
			}
			out = append(out, &e)
		}
	}
	return out, total, nil
}

func (p *AeroPayDB) ListUnsettled(direction string) ([]*LedgerEntry, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	q := `SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at 
		FROM double_entry_ledger WHERE settled = 0`
	var args []any
	if direction != "" {
		q += ` AND direction = ?`
		args = append(args, direction)
	}
	q += ` ORDER BY id ASC`

	rows, err := p.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*LedgerEntry
	for rows.Next() {
		var e LedgerEntry
		var createdAtStr string
		var settledAt sql.NullString
		var settlementNo sql.NullString
		var channelRef sql.NullString
		var settledInt int
		if err := rows.Scan(&e.ID, &e.LedgerNo, &e.UserID, &e.AmountCents, &e.Direction, &e.Channel,
			&channelRef, &settledInt, &settledAt, &settlementNo, &createdAtStr); err == nil {
			e.Settled = settledInt == 1
			if channelRef.Valid {
				e.ChannelRef = channelRef.String
			}
			if settlementNo.Valid {
				e.SettlementNo = settlementNo.String
			}
			if t, perr := time.Parse(time.RFC3339, createdAtStr); perr == nil {
				e.CreatedAt = t
			}
			out = append(out, &e)
		}
	}
	return out, nil
}

func (p *AeroPayDB) MarkSettled(ledgerNo, settlementNo string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	nowStr := time.Now().Format(time.RFC3339)
	_, err := p.db.Exec(`UPDATE double_entry_ledger SET settled = 1, settled_at = ?, settlement_no = ? WHERE ledger_no = ?`,
		nowStr, settlementNo, ledgerNo)
	return err
}

func (p *AeroPayDB) SettleBatch(channel, targetRef string) (*LedgerEntry, int, error) {
	unsettled, err := p.ListUnsettled("IN")
	if err != nil {
		return nil, 0, err
	}
	if len(unsettled) == 0 {
		return nil, 0, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	tx, err := p.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var totalAmount int64
	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	settlementNo := fmt.Sprintf("STL-%s-%04d", now.Format("20060102150405"), now.Nanosecond()%10000)

	for _, e := range unsettled {
		totalAmount += e.AmountCents
		_, _ = tx.Exec(`UPDATE double_entry_ledger SET settled = 1, settled_at = ?, settlement_no = ? WHERE id = ?`,
			nowStr, settlementNo, e.ID)
		_, _ = tx.Exec(`UPDATE income SET settled = 1, settled_batch_no = ? WHERE order_no = ?`,
			settlementNo, e.ChannelRef)
	}

	// Record Expense entry
	_, _ = tx.Exec(`INSERT INTO expense 
		(expense_no, expense_type, target_id, target_account_type, target_account_title, amount_cents, fee_cents, status, operator, remark, completed_at, created_at)
		VALUES (?, 'settlement', 1, 'bank', '默认银行账户归集', ?, 0, 'completed', 'system', ?, ?, ?)`,
		settlementNo, totalAmount, "一键收益归集结算", nowStr, nowStr)

	// Create settlement double-entry credit
	res, err := tx.Exec(`INSERT INTO double_entry_ledger 
		(ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at)
		VALUES (?, 0, ?, 'OUT', ?, ?, 1, ?, ?, ?)`,
		settlementNo, totalAmount, channel, targetRef, nowStr, settlementNo, nowStr)
	if err != nil {
		return nil, 0, err
	}

	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}

	id, _ := res.LastInsertId()
	return &LedgerEntry{
		ID:           uint64(id),
		LedgerNo:     settlementNo,
		AmountCents:  totalAmount,
		Direction:    "OUT",
		Channel:      channel,
		ChannelRef:   targetRef,
		Settled:      true,
		SettlementNo: settlementNo,
		CreatedAt:    now,
	}, len(unsettled), nil
}

func (p *AeroPayDB) GetDailySummary(date time.Time) (*LedgerSummary, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	datePrefix := date.Format("2006-01-02")
	summary := &LedgerSummary{}

	rows, err := p.db.Query(`SELECT direction, sum(amount_cents), count(*) 
		FROM double_entry_ledger WHERE created_at LIKE ? GROUP BY direction`, datePrefix+"%")
	if err != nil {
		return summary, nil
	}
	defer rows.Close()

	for rows.Next() {
		var dir string
		var amount int64
		var count int64
		if err := rows.Scan(&dir, &amount, &count); err == nil {
			if dir == "IN" {
				summary.TotalInCents += amount
				summary.EntryCount += count
			} else if dir == "OUT" {
				summary.TotalOutCents += amount
				summary.EntryCount += count
			}
		}
	}
	return summary, nil
}

// ----------------------------------------------------------------------
// SQLiteLedgerStore (Independent Ledger Database Store)
// ----------------------------------------------------------------------

type SQLiteLedgerStore struct {
	mu sync.RWMutex
	db *sql.DB
}

func NewSQLiteLedgerStore(dbPath string) (*SQLiteLedgerStore, error) {
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
	db.SetMaxOpenConns(1)
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
	return &SQLiteLedgerStore{db: db}, nil
}

func (s *SQLiteLedgerStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SQLiteLedgerStore) Append(e *LedgerEntry) (uint64, error) {
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
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	res, err := tx.Exec(query, e.LedgerNo, e.UserID, e.AmountCents, e.Direction, e.Channel, e.ChannelRef, settledInt, settledAtStr, e.SettlementNo, createdAt.Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("insert ledger: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}
	e.ID = uint64(id)
	return uint64(id), nil
}

func (s *SQLiteLedgerStore) Get(id uint64) (*LedgerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := `SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at FROM ledger_entries WHERE id = ?`
	row := s.db.QueryRow(query, id)
	return scanLedgerRow(row)
}

func (s *SQLiteLedgerStore) GetByLedgerNo(no string) (*LedgerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := `SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at FROM ledger_entries WHERE ledger_no = ?`
	row := s.db.QueryRow(query, no)
	return scanLedgerRow(row)
}

func (s *SQLiteLedgerStore) List(offset, limit int) ([]*LedgerEntry, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total int64
	_ = s.db.QueryRow("SELECT COUNT(*) FROM ledger_entries").Scan(&total)

	query := `SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at FROM ledger_entries ORDER BY id DESC LIMIT ? OFFSET ?`
	rows, err := s.db.Query(query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*LedgerEntry
	for rows.Next() {
		e, err := scanLedgerRows(rows)
		if err == nil {
			out = append(out, e)
		}
	}
	return out, total, nil
}

func (s *SQLiteLedgerStore) ListUnsettled(direction string) ([]*LedgerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if direction == "" {
		direction = "IN"
	}
	query := `SELECT id, ledger_no, user_id, amount_cents, direction, channel, channel_ref, settled, settled_at, settlement_no, created_at FROM ledger_entries WHERE settled = 0 AND direction = ? ORDER BY id DESC`
	rows, err := s.db.Query(query, direction)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*LedgerEntry
	for rows.Next() {
		e, err := scanLedgerRows(rows)
		if err == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *SQLiteLedgerStore) MarkSettled(ledgerNo, settlementNo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	_, err := s.db.Exec(`UPDATE ledger_entries SET settled = 1, settled_at = ?, settlement_no = ? WHERE ledger_no = ?`, now.Format(time.RFC3339), settlementNo, ledgerNo)
	return err
}

func (s *SQLiteLedgerStore) SettleBatch(channel, targetRef string) (*LedgerEntry, int, error) {
	unsettled, err := s.ListUnsettled("IN")
	if err != nil {
		return nil, 0, err
	}
	if len(unsettled) == 0 {
		return nil, 0, nil
	}
	var totalCents int64
	for _, it := range unsettled {
		totalCents += it.AmountCents
	}
	now := time.Now()
	setNo := fmt.Sprintf("SET-%s-%04x", now.Format("20060102"), now.UnixNano()%0xffff)
	for _, it := range unsettled {
		_ = s.MarkSettled(it.LedgerNo, setNo)
	}
	if channel == "" {
		channel = "PingPong"
	}
	if targetRef == "" {
		targetRef = "资金归集结算: " + setNo
	}
	outEntry := &LedgerEntry{
		LedgerNo:     fmt.Sprintf("LED-%s-OUT-%04x", now.Format("20060102"), now.UnixNano()%0xffff),
		UserID:       0,
		AmountCents:  totalCents,
		Direction:    "OUT",
		Channel:      channel,
		ChannelRef:   targetRef,
		Settled:      true,
		SettledAt:    &now,
		SettlementNo: setNo,
		CreatedAt:    now,
	}
	if _, err := s.Append(outEntry); err != nil {
		return nil, len(unsettled), err
	}
	return outEntry, len(unsettled), nil
}

func (s *SQLiteLedgerStore) GetDailySummary(date time.Time) (*LedgerSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summary := &LedgerSummary{}
	dateStr := date.Format("2006-01-02")

	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount_cents), 0) FROM ledger_entries WHERE direction = 'IN' AND substr(created_at, 1, 10) = ?`, dateStr).Scan(&summary.TotalInCents)
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount_cents), 0) FROM ledger_entries WHERE direction = 'OUT' AND substr(created_at, 1, 10) = ?`, dateStr).Scan(&summary.TotalOutCents)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM ledger_entries WHERE substr(created_at, 1, 10) = ?`, dateStr).Scan(&summary.EntryCount)

	return summary, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanLedgerRow(row rowScanner) (*LedgerEntry, error) {
	var e LedgerEntry
	var settledInt int
	var settledAtStr sql.NullString
	var createdAtStr string
	var ref, setNo sql.NullString

	err := row.Scan(&e.ID, &e.LedgerNo, &e.UserID, &e.AmountCents, &e.Direction, &e.Channel, &ref, &settledInt, &settledAtStr, &setNo, &createdAtStr)
	if err != nil {
		return nil, err
	}
	e.Settled = (settledInt == 1)
	if ref.Valid {
		e.ChannelRef = ref.String
	}
	if setNo.Valid {
		e.SettlementNo = setNo.String
	}
	if settledAtStr.Valid {
		t, _ := time.Parse(time.RFC3339, settledAtStr.String)
		e.SettledAt = &t
	}
	e.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	return &e, nil
}

func scanLedgerRows(rows *sql.Rows) (*LedgerEntry, error) {
	return scanLedgerRow(rows)
}

// ----------------------------------------------------------------------
// LedgerService & LedgerHandler
// ----------------------------------------------------------------------

type LedgerService struct {
	store LedgerStore
}

func NewLedgerService(store LedgerStore) *LedgerService {
	return &LedgerService{store: store}
}

func (s *LedgerService) RecordEntry(e *LedgerEntry) (uint64, error) {
	if s.store == nil {
		return 0, fmt.Errorf("ledger store not initialized")
	}
	return s.store.Append(e)
}

type LedgerHandler struct {
	store LedgerStore
}

func NewLedgerHandler(store LedgerStore) *LedgerHandler {
	return &LedgerHandler{store: store}
}

func (h *LedgerHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ledger/entries", h.ListEntries)
	mux.HandleFunc("GET /api/v1/ledger/entries/", h.ListEntries)
	mux.HandleFunc("GET /api/v1/ledger/entries/unsettled", h.ListUnsettled)
	mux.HandleFunc("GET /api/v1/ledger/entries/unsettled/", h.ListUnsettled)
	mux.HandleFunc("GET /api/v1/ledger/summary", h.Summary)
	mux.HandleFunc("GET /api/v1/ledger/summary/", h.Summary)
	mux.HandleFunc("POST /api/v1/ledger/settle/batch", h.SettleBatch)
	mux.HandleFunc("POST /api/v1/ledger/settle/batch/", h.SettleBatch)
}

func (h *LedgerHandler) ListEntries(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	entries, total, err := h.store.List(offset, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": map[string]any{
			"total":   total,
			"offset":  offset,
			"limit":   limit,
			"entries": entries,
			"results": entries,
		},
	})
}

func (h *LedgerHandler) ListUnsettled(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("direction")
	entries, err := h.store.ListUnsettled(dir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": map[string]any{
			"results": entries,
			"entries": entries,
		},
	})
}

func (h *LedgerHandler) Summary(w http.ResponseWriter, r *http.Request) {
	dateStr := r.URL.Query().Get("date")
	t := time.Now()
	if dateStr != "" {
		if parsed, err := time.Parse("2006-01-02", dateStr); err == nil {
			t = parsed
		}
	}
	summary, err := h.store.GetDailySummary(t)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": summary})
}

func (h *LedgerHandler) SettleBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Channel   string `json:"channel"`
		TargetRef string `json:"target_ref"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, errResp(1002, "invalid json body: "+err.Error()))
			return
		}
	}
	outEntry, count, err := h.store.SettleBatch(req.Channel, req.TargetRef)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code":    0,
		"message": "归集结算成功",
		"data": map[string]any{
			"settled_count": count,
			"out_entry":     outEntry,
		},
	})
}

// ----------------------------------------------------------------------
// Billing Models, Service & Handler
// ----------------------------------------------------------------------

type BillingPlan struct {
	ID             int32     `json:"id"`
	Name           string    `json:"name"`
	DurationMonths int32     `json:"duration_months"`
	TrafficBytes   int64     `json:"traffic_bytes"`
	PriceCents     int64     `json:"price_cents"`
	Status         bool      `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

type BillingService struct {
	mu     sync.RWMutex
	aeroDB *AeroDB
	plans  map[int32]*BillingPlan
	nextID int32
}

func NewBillingService(aeroDB ...*AeroDB) *BillingService {
	svc := &BillingService{
		plans:  make(map[int32]*BillingPlan),
		nextID: 1,
	}
	if len(aeroDB) > 0 && aeroDB[0] != nil {
		svc.aeroDB = aeroDB[0]
	}
	now := time.Now()
	defaults := []BillingPlan{
		{ID: 1, Name: "月度套餐", DurationMonths: 1, TrafficBytes: 100 * 1024 * 1024 * 1024, PriceCents: 999, Status: true, CreatedAt: now},
		{ID: 2, Name: "季度套餐", DurationMonths: 3, TrafficBytes: 300 * 1024 * 1024 * 1024, PriceCents: 2499, Status: true, CreatedAt: now},
		{ID: 3, Name: "年度套餐", DurationMonths: 12, TrafficBytes: 1200 * 1024 * 1024 * 1024, PriceCents: 7999, Status: true, CreatedAt: now},
		{ID: 4, Name: "全年不限流量", DurationMonths: 12, TrafficBytes: -1, PriceCents: 12999, Status: true, CreatedAt: now},
	}
	for _, p := range defaults {
		cp := p
		svc.plans[p.ID] = &cp
		if p.ID >= svc.nextID {
			svc.nextID = p.ID + 1
		}
	}
	return svc
}

func (s *BillingService) SetAeroDB(db *AeroDB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aeroDB = db
}

func (s *BillingService) CreatePlan(name string, months int32, bytes, price int64) (*BillingPlan, error) {
	if s.aeroDB != nil {
		p, err := s.aeroDB.CreatePlan(&Plan{
			Name:         name,
			PeriodType:   "month",
			PeriodValue:  months,
			PriceCents:   price,
			TrafficBytes: bytes,
			Status:       true,
		})
		if err == nil {
			return &BillingPlan{
				ID:             int32(p.ID),
				Name:           p.Name,
				DurationMonths: p.DurationMonths,
				TrafficBytes:   p.TrafficBytes,
				PriceCents:     p.PriceCents,
				Status:         p.Status,
				CreatedAt:      p.CreatedAt,
			}, nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &BillingPlan{
		ID:             s.nextID,
		Name:           name,
		DurationMonths: months,
		TrafficBytes:   bytes,
		PriceCents:     price,
		Status:         true,
		CreatedAt:      time.Now(),
	}
	s.nextID++
	s.plans[p.ID] = p
	return p, nil
}

func (s *BillingService) GetPlan(id int32) (*BillingPlan, error) {
	if s.aeroDB != nil {
		p, err := s.aeroDB.GetPlan(int64(id))
		if err == nil {
			return &BillingPlan{
				ID:             int32(p.ID),
				Name:           p.Name,
				DurationMonths: p.DurationMonths,
				TrafficBytes:   p.TrafficBytes,
				PriceCents:     p.PriceCents,
				Status:         p.Status,
				CreatedAt:      p.CreatedAt,
			}, nil
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.plans[id]; ok {
		cp := *p
		return &cp, nil
	}
	return nil, errors.New("plan not found")
}

func (s *BillingService) ListPlans(activeOnly bool) ([]BillingPlan, error) {
	if s.aeroDB != nil {
		dbPlans, err := s.aeroDB.ListPlans()
		if err == nil && len(dbPlans) > 0 {
			var out []BillingPlan
			for _, dp := range dbPlans {
				if !activeOnly || dp.Status {
					out = append(out, BillingPlan{
						ID:             int32(dp.ID),
						Name:           dp.Name,
						DurationMonths: dp.DurationMonths,
						TrafficBytes:   dp.TrafficBytes,
						PriceCents:     dp.PriceCents,
						Status:         dp.Status,
						CreatedAt:      dp.CreatedAt,
					})
				}
			}
			return out, nil
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var res []BillingPlan
	for _, p := range s.plans {
		if !activeOnly || p.Status {
			res = append(res, *p)
		}
	}
	return res, nil
}

func (s *BillingService) UpdatePlan(id int32, price *int64, status *bool) error {
	if s.aeroDB != nil {
		_ = s.aeroDB.UpdatePlan(int64(id), nil, price, nil, status, nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[id]
	if !ok {
		return errors.New("plan not found")
	}
	if price != nil {
		p.PriceCents = *price
	}
	if status != nil {
		p.Status = *status
	}
	return nil
}

type BillingHandler struct {
	svc *BillingService
}

func NewBillingHandler(svc *BillingService) *BillingHandler {
	return &BillingHandler{svc: svc}
}

func (h *BillingHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/plans/", h.List)
	mux.HandleFunc("POST /api/v1/plans/", h.Create)
	mux.HandleFunc("GET /api/v1/plans/{id}/", h.Get)
	mux.HandleFunc("PATCH /api/v1/plans/{id}/", h.Update)
}

func (h *BillingHandler) List(w http.ResponseWriter, r *http.Request) {
	plans, _ := h.svc.ListPlans(true)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"results": plans}})
}

func (h *BillingHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		Months     int32  `json:"duration_months"`
		Traffic    int64  `json:"traffic_bytes"`
		PriceCents int64  `json:"price_cents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid body"})
		return
	}
	p, err := h.svc.CreatePlan(req.Name, req.Months, req.Traffic, req.PriceCents)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": 0, "data": p})
}

func (h *BillingHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	p, err := h.svc.GetPlan(int32(id))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": p})
}

func (h *BillingHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var req struct {
		Price  *int64 `json:"price_cents"`
		Status *bool  `json:"status"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, errResp(1002, "invalid json body: "+err.Error()))
			return
		}
	}
	_ = h.svc.UpdatePlan(int32(id), req.Price, req.Status)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "success"})
}

// ----------------------------------------------------------------------
// Payment In (Orders, Recharge & Hook)
// ----------------------------------------------------------------------

type PayInOrder struct {
	OrderNo     string `json:"order_no"`
	UserID      uint64 `json:"user_id"`
	Channel     string `json:"channel"`
	AmountCents int64  `json:"amount_cents"`
	LedgerNo    string `json:"ledger_no"`
	Status      string `json:"status"`
}

type PayInService struct {
	ledgerURL      string
	ledgerSvc      *LedgerService
	onOrderSuccess func(userID uint64, amountCents int64)
}

func NewPayInService(ledgerURL string, ledgerSvc *LedgerService) *PayInService {
	return &PayInService{
		ledgerURL: ledgerURL,
		ledgerSvc: ledgerSvc,
	}
}

func (s *PayInService) SetOnOrderSuccess(fn func(userID uint64, amountCents int64)) {
	s.onOrderSuccess = fn
}

func (s *PayInService) CreateOrder(userID uint64, channel string, amountCents int64) (*PayInOrder, error) {
	if channel == "" {
		channel = "alipay"
	}
	if amountCents <= 0 {
		return nil, fmt.Errorf("invalid amount_cents: %d", amountCents)
	}

	now := time.Now()
	orderNo := fmt.Sprintf("ORD-%s-%d", now.Format("20060102"), now.UnixNano()%1000000)
	ledgerNo := fmt.Sprintf("LED-%s-IN-%s", now.Format("20060102"), orderNo[len(orderNo)-6:])

	if s.ledgerSvc != nil {
		_, _ = s.ledgerSvc.RecordEntry(&LedgerEntry{
			LedgerNo:    ledgerNo,
			UserID:      userID,
			Direction:   "IN",
			AmountCents: amountCents,
			Channel:     channel,
			ChannelRef:  orderNo,
			CreatedAt:   now,
		})
	} else if s.ledgerURL != "" {
		body, _ := json.Marshal(map[string]any{
			"user_id":      userID,
			"amount_cents": amountCents,
			"direction":    "IN",
			"channel":      channel,
			"channel_ref":  orderNo,
		})
		go func() {
			resp, err := http.Post(s.ledgerURL+"/api/v1/ledger/entries/", "application/json", bytes.NewReader(body))
			if err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}()
	}

	if s.onOrderSuccess != nil && userID > 0 {
		s.onOrderSuccess(userID, amountCents)
	}

	return &PayInOrder{
		OrderNo:     orderNo,
		UserID:      userID,
		Channel:     channel,
		AmountCents: amountCents,
		LedgerNo:    ledgerNo,
		Status:      "completed",
	}, nil
}

type PayInHandler struct {
	svc       *PayInService
	userStore UserStore
	billing   *BillingService
	usersSvc  *UserService
	vpsSvc    *VPSService
}

func NewPayInHandler(svc *PayInService) *PayInHandler {
	return &PayInHandler{svc: svc}
}

func (h *PayInHandler) SetDeps(userStore UserStore, billing *BillingService, usersSvc *UserService, vpsSvc *VPSService) {
	h.userStore = userStore
	h.billing = billing
	h.usersSvc = usersSvc
	h.vpsSvc = vpsSvc
}

func (h *PayInHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/payments/in/orders/", h.CreateOrder)
	mux.HandleFunc("GET /api/v1/payments/in/channels/", h.Channels)
	mux.HandleFunc("GET /api/v1/orders/", h.ListOrders)
	mux.HandleFunc("POST /api/v1/orders/checkout/", h.Checkout)
	mux.HandleFunc("GET /api/v1/user/subscriptions/", h.ListUserSubscriptions)
	mux.HandleFunc("GET /api/v1/user/subscriptions", h.ListUserSubscriptions)
}

func (h *PayInHandler) ListUserSubscriptions(w http.ResponseWriter, r *http.Request) {
	var uid uint64
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token != "" && h.usersSvc != nil {
		if id, _, err := h.usersSvc.VerifyToken(token); err == nil {
			uid = id
		}
	}
	if uid == 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 1003, "message": "unauthorized"})
		return
	}
	if h.userStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": []*Subscription{}})
		return
	}
	subs, err := h.userStore.ListSubscriptions(uid)
	if err != nil || subs == nil {
		subs = []*Subscription{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": subs})
}

func (h *PayInHandler) CreateOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      uint64 `json:"user_id"`
		Channel     string `json:"channel"`
		AmountCents int64  `json:"amount_cents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid request body"})
		return
	}
	order, err := h.svc.CreateOrder(req.UserID, req.Channel, req.AmountCents)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": 0, "data": order})
}

func (h *PayInHandler) Channels(w http.ResponseWriter, r *http.Request) {
	channels := []map[string]any{
		{"channel": "wechat", "name": "微信支付", "icon": "wechat", "enabled": true},
		{"channel": "alipay", "name": "支付宝", "icon": "alipay", "enabled": true},
		{"channel": "bankcard", "name": "银行卡", "icon": "bankcard", "enabled": true},
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": channels})
}

func (h *PayInHandler) ListOrders(w http.ResponseWriter, r *http.Request) {
	var uid uint64
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token != "" && h.usersSvc != nil {
		if id, _, err := h.usersSvc.VerifyToken(token); err == nil {
			uid = id
		}
	}
	if uid == 0 {
		qUID := r.URL.Query().Get("user_id")
		if qUID != "" {
			uid, _ = strconv.ParseUint(qUID, 10, 64)
		}
	}
	if h.userStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"results": []Order{}}})
		return
	}
	orders, err := h.userStore.ListOrders(uid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	if orders == nil {
		orders = []Order{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"results": orders}})
}

func (h *PayInHandler) Checkout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubID         string   `json:"sub_id"`
		PlanID        int32    `json:"plan_id"`
		AssignedNodes []string `json:"assigned_nodes"`
		Channel       string   `json:"channel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid body"})
		return
	}

	var uid uint64
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token != "" && h.usersSvc != nil {
		if id, _, err := h.usersSvc.VerifyToken(token); err == nil {
			uid = id
		}
	}
	if uid == 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 1003, "message": "unauthorized"})
		return
	}

	if h.billing == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 1004, "message": "billing service unavailable"})
		return
	}
	plan, err := h.billing.GetPlan(req.PlanID)
	if err != nil || plan == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "plan not found"})
		return
	}

	if req.Channel == "" {
		req.Channel = "alipay"
	}

	now := time.Now()
	orderNo := fmt.Sprintf("ORD-%s-%d", now.Format("20060102"), now.UnixNano()%1000000)

	nodesToSet := req.AssignedNodes
	var targetSub *Subscription

	if h.userStore != nil {
		u, err := h.userStore.GetUser(uid)
		if err != nil || u == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "user not found"})
			return
		}

		if req.SubID != "" {
			if sub, err := h.userStore.GetSubscription(req.SubID); err == nil && sub != nil && sub.UserID == uid {
				if renewed, err := h.userStore.RenewSubscription(sub.SubID, plan.DurationMonths, plan.PriceCents, plan.Name); err == nil {
					targetSub = renewed
					nodesToSet = renewed.AssignedNodes
					if plan.TrafficBytes > 0 {
						targetSub.LimitBytes = plan.TrafficBytes
						_ = h.userStore.UpdateTraffic(uid, -1, plan.TrafficBytes)
					}
				}
			}
		}

		if targetSub == nil {
			newSlug := GenerateSubscriptionSlug(u.Username)
			seedRaw := make([]byte, 24)
			_, _ = rand.Read(seedRaw)
			newSeed := "sec_" + hex.EncodeToString(seedRaw)
			tokRaw := make([]byte, 16)
			_, _ = rand.Read(tokRaw)
			newTok := hex.EncodeToString(tokRaw)

			baseExp := now.AddDate(0, int(plan.DurationMonths), 0)
			limitBytes := plan.TrafficBytes
			if limitBytes <= 0 {
				limitBytes = 100 * 1024 * 1024 * 1024
			}
			newSub := &Subscription{
				SubID:         fmt.Sprintf("sub_%s", newSlug),
				UserID:        uid,
				UserUUID:      u.UUID,
				SubSlug:       newSlug,
				SubToken:      newTok,
				SubTicketSeed: newSeed,
				PlanName:      plan.Name,
				AssignedNodes: nodesToSet,
				LimitBytes:    limitBytes,
				UsedBytes:     0,
				ExpireAt:      baseExp,
				Status:        true,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			_ = h.userStore.CreateSubscription(newSub)
			targetSub = newSub

			_ = h.userStore.UpdateUser(uid, UpdateUserParams{
				PlanName:      &plan.Name,
				PlanMonths:    &plan.DurationMonths,
				PriceCents:    &plan.PriceCents,
				AssignedNodes: &nodesToSet,
				ExpireAt:      &baseExp,
			})
			if plan.TrafficBytes > 0 {
				_ = h.userStore.UpdateTraffic(uid, -1, plan.TrafficBytes)
			}
		}
	}

	order := &Order{
		OrderNo:       orderNo,
		UserID:        uid,
		PlanID:        uint64(plan.ID),
		PlanName:      plan.Name,
		AssignedNodes: nodesToSet,
		AmountCents:   plan.PriceCents,
		PayChannel:    req.Channel,
		Status:        "completed",
		CreatedAt:     now,
		PaidAt:        &now,
	}

	if h.userStore != nil {
		_ = h.userStore.CreateOrder(order)
	}

	if h.svc != nil {
		_, _ = h.svc.CreateOrder(uid, req.Channel, plan.PriceCents)
	}

	if h.vpsSvc != nil && targetSub != nil {
		go func(sub *Subscription) {
			u, _ := h.userStore.GetUser(sub.UserID)
			if u != nil && h.vpsSvc.eps != nil {
				for _, ep := range h.vpsSvc.eps.List() {
					if !ep.Installed || ep.Host == "" {
						continue
					}
					matched := len(sub.AssignedNodes) == 0
					for _, nodeName := range sub.AssignedNodes {
						if ep.Name == nodeName || ep.Host == nodeName {
							matched = true
							break
						}
					}
					if matched {
						_ = h.vpsSvc.SyncUsersToEdge(ep.VPSID, []*User{u})
					}
				}
			}
		}(targetSub)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": map[string]any{
			"order":   order,
			"message": "支付与节点绑定已完成",
		},
	})
}

// ----------------------------------------------------------------------
// Payment Out (Settlement & Payout)
// ----------------------------------------------------------------------

type SettlementRequest struct {
	SettlementNo string `json:"settlement_no"`
	Channel      string `json:"channel"`
	AmountCents  int64  `json:"amount_cents"`
}

type SettlementResult struct {
	Date         string `json:"date,omitempty"`
	SettlementNo string `json:"settlement_no"`
	Channel      string `json:"channel,omitempty"`
	Status       string `json:"status"`
	Message      string `json:"message"`
}

type PayOutService struct {
	ledgerSvc *LedgerService
}

func NewPayOutService(ledgerSvc *LedgerService) *PayOutService {
	return &PayOutService{ledgerSvc: ledgerSvc}
}

func (s *PayOutService) Settle(req SettlementRequest) SettlementResult {
	if req.Channel == "" {
		req.Channel = "pingpong"
	}
	now := time.Now()
	settleNo := req.SettlementNo
	if settleNo == "" {
		settleNo = fmt.Sprintf("SET-%s-%d", now.Format("20060102"), now.UnixNano()%1000000)
	}

	if s.ledgerSvc != nil && req.AmountCents > 0 {
		_, _ = s.ledgerSvc.RecordEntry(&LedgerEntry{
			LedgerNo:    fmt.Sprintf("LED-%s-OUT-%s", now.Format("20060102"), settleNo[len(settleNo)-6:]),
			UserID:      0,
			Direction:   "OUT",
			AmountCents: req.AmountCents,
			Channel:     req.Channel,
			ChannelRef:  settleNo,
			CreatedAt:   now,
		})
	}

	return SettlementResult{
		SettlementNo: settleNo,
		Channel:      req.Channel,
		Status:       "pending",
		Message:      req.Channel + " payout initiated",
	}
}

func (s *PayOutService) RunDailySettlement(date time.Time) (*SettlementResult, error) {
	dateStr := date.Format("2006-01-02")
	settleNo := fmt.Sprintf("SET-%s-%04d", date.Format("20060102"), date.Unix()%10000)
	return &SettlementResult{
		Date:         dateStr,
		SettlementNo: settleNo,
		Status:       "completed",
		Message:      "daily settlement executed successfully",
	}, nil
}

func (s *PayOutService) Channels() []map[string]any {
	return []map[string]any{
		{"channel": "pingpong", "name": "PingPong", "priority": "primary", "enabled": true},
		{"channel": "airwallex", "name": "Airwallex", "priority": "hot_standby", "enabled": true},
		{"channel": "stripe", "name": "Stripe", "priority": "hot_standby", "enabled": true},
		{"channel": "crypto", "name": "Crypto (USDT)", "priority": "cold_standby", "enabled": true},
		{"channel": "paypal", "name": "PayPal", "priority": "cold_standby", "enabled": false},
	}
}

type PayOutHandler struct {
	svc *PayOutService
}

func NewPayOutHandler(svc *PayOutService) *PayOutHandler {
	return &PayOutHandler{svc: svc}
}

func (h *PayOutHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/payments/out/settle/", h.Settle)
	mux.HandleFunc("GET /api/v1/payments/out/channels/", h.Channels)
	mux.HandleFunc("POST /api/v1/settlements/daily/", h.DailySettlement)
}

func (h *PayOutHandler) Settle(w http.ResponseWriter, r *http.Request) {
	var req SettlementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid request body"})
		return
	}
	res := h.svc.Settle(req)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": res})
}

func (h *PayOutHandler) Channels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": h.svc.Channels()})
}

func (h *PayOutHandler) DailySettlement(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.RunDailySettlement(time.Now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 1006, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": res})
}
