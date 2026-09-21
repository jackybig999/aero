// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// LedgerEntry represents an immutable financial journal entry.
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

	// Daily IN
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount_cents), 0) FROM ledger_entries WHERE direction = 'IN' AND substr(created_at, 1, 10) = ?`, dateStr).Scan(&summary.TotalInCents)
	// Daily OUT
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(amount_cents), 0) FROM ledger_entries WHERE direction = 'OUT' AND substr(created_at, 1, 10) = ?`, dateStr).Scan(&summary.TotalOutCents)
	// Daily Count
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

// LedgerHandler provides HTTP endpoints for ledger inspection.
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
	_ = json.NewDecoder(r.Body).Decode(&req)
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

// LedgerService encapsulates high-level financial ledger operations.
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
