// Copyright 2026 AERO Protocol Contributors
// AERO Platform Master Database (aero.db) - 100% Pure Go SQLite (Zero CGO)
package mid

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Plan struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	PeriodType     string    `json:"period_type"`
	PeriodValue    int32     `json:"period_value"`
	DurationMonths int32     `json:"duration_months"`
	PriceCents     int64     `json:"price_cents"`
	TrafficBytes   int64     `json:"traffic_bytes"`
	AssignedNodes  []string  `json:"assigned_nodes"`
	Status         bool      `json:"status"`
	SortOrder      int       `json:"sort_order"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type AeroDB struct {
	mu         sync.RWMutex
	db         *sql.DB
	payDB      *AeroPayDB
	nodesCache []*Node
}

func NewAeroDB(dbPath string, payDB *AeroPayDB) (*AeroDB, error) {
	if dbPath == "" {
		dbPath = filepath.Join("data", "aero.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("aero db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open aero db: %w", err)
	}
	db.SetMaxOpenConns(1)

	schema := `
	CREATE TABLE IF NOT EXISTS user (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uuid TEXT UNIQUE NOT NULL,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT DEFAULT '',
		phone TEXT DEFAULT '',
		email_verified INTEGER DEFAULT 0,
		phone_verified INTEGER DEFAULT 0,
		role TEXT DEFAULT 'user',
		status INTEGER DEFAULT 1,
		is_staff INTEGER DEFAULT 0,
		plan_name TEXT DEFAULT '',
		plan_months INTEGER DEFAULT 0,
		price_cents INTEGER DEFAULT 0,
		sub_slug TEXT DEFAULT '',
		sub_token TEXT DEFAULT '',
		sub_ticket_seed TEXT DEFAULT '',
		assigned_nodes_json TEXT DEFAULT '[]',
		expire_at TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_user_username ON user(username);
	CREATE INDEX IF NOT EXISTS idx_user_slug ON user(sub_slug);

	CREATE TABLE IF NOT EXISTS plan (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		period_type TEXT NOT NULL,
		period_value INTEGER NOT NULL,
		price_cents INTEGER NOT NULL,
		traffic_bytes INTEGER NOT NULL,
		assigned_nodes_json TEXT DEFAULT '[]',
		status INTEGER DEFAULT 1,
		sort_order INTEGER DEFAULT 0,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS subscription (
		sub_id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		user_uuid TEXT NOT NULL,
		sub_slug TEXT UNIQUE NOT NULL,
		sub_token TEXT NOT NULL,
		sub_ticket_seed TEXT NOT NULL,
		plan_id INTEGER DEFAULT 0,
		plan_name TEXT NOT NULL,
		assigned_nodes_json TEXT DEFAULT '[]',
		limit_bytes INTEGER NOT NULL,
		used_bytes INTEGER DEFAULT 0,
		expire_at TEXT NOT NULL,
		switch_status TEXT DEFAULT 'on',
		status INTEGER DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_sub_slug ON subscription(sub_slug);
	CREATE INDEX IF NOT EXISTS idx_sub_user ON subscription(user_id);

	CREATE TABLE IF NOT EXISTS order_record (
		order_no TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		sub_id TEXT DEFAULT '',
		plan_id INTEGER NOT NULL,
		plan_name TEXT NOT NULL,
		assigned_nodes_json TEXT DEFAULT '[]',
		amount_cents INTEGER NOT NULL,
		pay_channel TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		paid_at TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_order_user ON order_record(user_id);

	CREATE TABLE IF NOT EXISTS traffic (
		user_id INTEGER PRIMARY KEY,
		used_bytes INTEGER DEFAULT 0,
		limit_bytes INTEGER DEFAULT 107374182400,
		is_connected INTEGER DEFAULT 0,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS node (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		vps_id INTEGER DEFAULT 0,
		name TEXT UNIQUE NOT NULL,
		region TEXT DEFAULT 'global',
		address TEXT NOT NULL,
		protocol TEXT DEFAULT 'quic',
		port INTEGER DEFAULT 443,
		purity_score INTEGER DEFAULT 100,
		latency_ms INTEGER DEFAULT 35,
		bandwidth_mbps INTEGER DEFAULT 1000,
		weight INTEGER DEFAULT 10,
		status INTEGER DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS vps (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		ip TEXT NOT NULL,
		ssh_port INTEGER DEFAULT 22,
		ssh_username TEXT DEFAULT 'root',
		ssh_password_enc BLOB,
		domain TEXT DEFAULT '',
		remark TEXT DEFAULT '',
		status TEXT DEFAULT 'registered',
		health_score INTEGER DEFAULT 100,
		tier INTEGER DEFAULT 2,
		capacity_state TEXT DEFAULT 'ready',
		installed INTEGER DEFAULT 0,
		metrics_json TEXT DEFAULT '',
		purity_score INTEGER DEFAULT 100,
		ai_blocked INTEGER DEFAULT 0,
		google_clean INTEGER DEFAULT 1,
		cf_clean INTEGER DEFAULT 1,
		is_warp_egress INTEGER DEFAULT 0,
		last_probe_at TEXT,
		last_purity_probe_at TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init aero schema: %w", err)
	}

	a := &AeroDB{
		db:    db,
		payDB: payDB,
	}

	a.autoSeedDefaults(dbPath)
	a.refreshCaches()
	return a, nil
}

func (a *AeroDB) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

func (a *AeroDB) autoSeedDefaults(dbPath string) {
	// 1. Check if user table is empty, auto-migrate from users.json
	var userCount int
	_ = a.db.QueryRow(`SELECT count(*) FROM user`).Scan(&userCount)
	if userCount == 0 {
		candidates := []string{
			filepath.Join(filepath.Dir(dbPath), "users.json"),
			filepath.Join("vpn", "data", "users.json"),
			filepath.Join("data", "users.json"),
		}
		for _, c := range candidates {
			if b, err := os.ReadFile(c); err == nil && len(b) > 0 {
				a.migrateUsersJSON(b)
				break
			}
		}
	}

	// 2. Ensure default plans exist
	var planCount int
	_ = a.db.QueryRow(`SELECT count(*) FROM plan`).Scan(&planCount)
	if planCount == 0 {
		now := time.Now().Format(time.RFC3339)
		_, _ = a.db.Exec(`INSERT INTO plan (name, period_type, period_value, price_cents, traffic_bytes, assigned_nodes_json, status, sort_order, created_at, updated_at) VALUES 
			('月度套餐', 'month', 1, 999, 107374182400, '[]', 1, 1, ?, ?),
			('季度套餐', 'month', 3, 2499, 322122547200, '[]', 1, 2, ?, ?),
			('年度套餐', 'year', 1, 7999, 1073741824000, '[]', 1, 3, ?, ?),
			('全年不限流量', 'year', 1, 12999, -1, '[]', 1, 4, ?, ?)`,
			now, now, now, now, now, now, now, now)
	}
}

func (a *AeroDB) migrateUsersJSON(data []byte) {
	var pf struct {
		Users         map[string]*User         `json:"users"`
		Orders        []*Order                 `json:"orders"`
		Traffic       map[string]*TrafficStats `json:"traffic"`
		Subscriptions map[string]*Subscription `json:"subscriptions"`
	}
	if err := json.Unmarshal(data, &pf); err != nil {
		return
	}

	tx, err := a.db.Begin()
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Format(time.RFC3339)

	// Migrate users
	for _, u := range pf.Users {
		if u == nil {
			continue
		}
		isStaffInt := 0
		if u.IsStaff {
			isStaffInt = 1
		}
		statusInt := 0
		if u.Status {
			statusInt = 1
		}
		nodesJSON, _ := json.Marshal(u.AssignedNodes)
		expStr := u.ExpireAt.Format(time.RFC3339)
		createdStr := u.CreatedAt.Format(time.RFC3339)
		if u.CreatedAt.IsZero() {
			createdStr = now
		}
		updatedStr := u.UpdatedAt.Format(time.RFC3339)
		if u.UpdatedAt.IsZero() {
			updatedStr = now
		}
		role := "user"
		if u.IsStaff {
			role = "superadmin"
		}

		_, _ = tx.Exec(`INSERT OR REPLACE INTO user 
			(id, uuid, username, password_hash, email, phone, role, status, is_staff, plan_name, plan_months, price_cents, sub_slug, sub_token, sub_ticket_seed, assigned_nodes_json, expire_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			u.ID, u.UUID, u.Username, u.PasswordHash, u.Email, u.Phone, role, statusInt, isStaffInt,
			u.PlanName, u.PlanMonths, u.PriceCents, u.SubSlug, u.SubToken, u.SubTicketSeed, string(nodesJSON), expStr, createdStr, updatedStr)
	}

	// Migrate subscriptions
	for _, s := range pf.Subscriptions {
		if s == nil {
			continue
		}
		statusInt := 0
		if s.Status {
			statusInt = 1
		}
		nodesJSON, _ := json.Marshal(s.AssignedNodes)
		expStr := s.ExpireAt.Format(time.RFC3339)
		createdStr := s.CreatedAt.Format(time.RFC3339)
		if s.CreatedAt.IsZero() {
			createdStr = now
		}
		updatedStr := s.UpdatedAt.Format(time.RFC3339)
		if s.UpdatedAt.IsZero() {
			updatedStr = now
		}
		sw := s.SwitchStatus
		if sw == "" {
			sw = "on"
			if !s.ExpireAt.IsZero() && time.Now().After(s.ExpireAt) {
				sw = "off"
			}
		}

		_, _ = tx.Exec(`INSERT OR REPLACE INTO subscription 
			(sub_id, user_id, user_uuid, sub_slug, sub_token, sub_ticket_seed, plan_id, plan_name, assigned_nodes_json, limit_bytes, used_bytes, expire_at, switch_status, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			s.SubID, s.UserID, s.UserUUID, s.SubSlug, s.SubToken, s.SubTicketSeed,
			s.PlanName, string(nodesJSON), s.LimitBytes, s.UsedBytes, expStr, sw, statusInt, createdStr, updatedStr)
	}

	// Migrate orders
	for _, o := range pf.Orders {
		if o == nil {
			continue
		}
		nodesJSON, _ := json.Marshal(o.AssignedNodes)
		createdStr := o.CreatedAt.Format(time.RFC3339)
		if o.CreatedAt.IsZero() {
			createdStr = now
		}
		var paidStr *string
		if o.PaidAt != nil {
			p := o.PaidAt.Format(time.RFC3339)
			paidStr = &p
		}

		_, _ = tx.Exec(`INSERT OR REPLACE INTO order_record 
			(order_no, user_id, sub_id, plan_id, plan_name, assigned_nodes_json, amount_cents, pay_channel, status, created_at, paid_at)
			VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?)`,
			o.OrderNo, o.UserID, o.PlanID, o.PlanName, string(nodesJSON), o.AmountCents, o.PayChannel, o.Status, createdStr, paidStr)

		if a.payDB != nil {
			_ = a.payDB.RecordIncome(o)
		}
	}

	// Migrate traffic
	for uidStr, t := range pf.Traffic {
		if t == nil {
			continue
		}
		var uid uint64
		_, _ = fmt.Sscanf(uidStr, "%d", &uid)
		if uid == 0 {
			uid = t.UserID
		}
		isConn := 0
		if t.IsConnected {
			isConn = 1
		}
		updatedStr := t.UpdatedAt.Format(time.RFC3339)
		if t.UpdatedAt.IsZero() {
			updatedStr = now
		}
		_, _ = tx.Exec(`INSERT OR REPLACE INTO traffic (user_id, used_bytes, limit_bytes, is_connected, updated_at)
			VALUES (?, ?, ?, ?, ?)`, uid, t.UsedBytes, t.LimitBytes, isConn, updatedStr)
	}

	_ = tx.Commit()
}

func (a *AeroDB) refreshCaches() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 1. Refresh nodes cache
	rows, err := a.db.Query(`SELECT id, vps_id, name, region, address, protocol, port, purity_score, latency_ms, bandwidth_mbps, weight, status, created_at, updated_at FROM node WHERE status = 1 ORDER BY weight DESC`)
	if err == nil {
		var list []*Node
		for rows.Next() {
			var n Node
			var statusInt int
			var createdStr, updatedStr string
			if scanErr := rows.Scan(&n.ID, &n.VPSID, &n.Name, &n.Region, &n.Address, &n.Protocol, &n.Port,
				&n.PurityScore, &n.LatencyMS, &n.BandwidthMB, &n.Weight, &statusInt, &createdStr, &updatedStr); scanErr == nil {
				n.Status = statusInt == 1
				list = append(list, &n)
			}
		}
		rows.Close()
		a.nodesCache = list
	}
}

// GetCachedNodes returns high-speed read-only slice of active nodes (zero SQLite lock contention).
func (a *AeroDB) GetCachedNodes() []*Node {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]*Node, len(a.nodesCache))
	copy(out, a.nodesCache)
	return out
}

// ----------------------------------------------------------------------
// UserStore Interface Implementations
// ----------------------------------------------------------------------

func (a *AeroDB) CreateUser(u *User) (uint64, error) {
	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	expStr := u.ExpireAt.Format(time.RFC3339)
	nodesJSON, _ := json.Marshal(u.AssignedNodes)
	statusInt := 0
	if u.Status {
		statusInt = 1
	}
	isStaffInt := 0
	if u.IsStaff {
		isStaffInt = 1
	}

	res, err := a.db.Exec(`INSERT INTO user 
		(uuid, username, password_hash, email, phone, role, status, is_staff, plan_name, plan_months, price_cents, sub_slug, sub_token, sub_ticket_seed, assigned_nodes_json, expire_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'user', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.UUID, u.Username, u.PasswordHash, u.Email, u.Phone, statusInt, isStaffInt,
		u.PlanName, u.PlanMonths, u.PriceCents, u.SubSlug, u.SubToken, u.SubTicketSeed, string(nodesJSON), expStr, nowStr, nowStr)
	if err != nil {
		return 0, fmt.Errorf("create user: %w", err)
	}

	id, _ := res.LastInsertId()
	u.ID = uint64(id)

	// Create initial subscription only when user explicitly has an assigned plan and expiration
	if u.SubSlug != "" && u.PlanName != "" && !u.ExpireAt.IsZero() {
		subID := fmt.Sprintf("sub_%s", u.SubSlug)
		_ = a.CreateSubscription(&Subscription{
			SubID:         subID,
			UserID:        u.ID,
			UserUUID:      u.UUID,
			SubSlug:       u.SubSlug,
			SubToken:      u.SubToken,
			SubTicketSeed: u.SubTicketSeed,
			PlanName:      u.PlanName,
			AssignedNodes: u.AssignedNodes,
			LimitBytes:    107374182400,
			UsedBytes:     0,
			ExpireAt:      u.ExpireAt,
			SwitchStatus:  "on",
			Status:        u.Status,
			CreatedAt:     now,
			UpdatedAt:     now,
		})
	}

	return u.ID, nil
}

func (a *AeroDB) GetUser(id uint64) (*User, error) {
	row := a.db.QueryRow(`SELECT id, uuid, username, password_hash, email, phone, role, status, is_staff, plan_name, plan_months, price_cents, sub_slug, sub_token, sub_ticket_seed, assigned_nodes_json, expire_at, created_at, updated_at 
		FROM user WHERE id = ?`, id)
	return a.scanUser(row)
}

func (a *AeroDB) GetUserByUsername(username string) (*User, error) {
	row := a.db.QueryRow(`SELECT id, uuid, username, password_hash, email, phone, role, status, is_staff, plan_name, plan_months, price_cents, sub_slug, sub_token, sub_ticket_seed, assigned_nodes_json, expire_at, created_at, updated_at 
		FROM user WHERE LOWER(username) = LOWER(?)`, username)
	return a.scanUser(row)
}

func (a *AeroDB) GetUserBySlug(slug string) (*User, error) {
	row := a.db.QueryRow(`SELECT id, uuid, username, password_hash, email, phone, role, status, is_staff, plan_name, plan_months, price_cents, sub_slug, sub_token, sub_ticket_seed, assigned_nodes_json, expire_at, created_at, updated_at 
		FROM user WHERE sub_slug = ?`, slug)
	return a.scanUser(row)
}

func (a *AeroDB) GetUserByEmail(email string) (*User, error) {
	row := a.db.QueryRow(`SELECT id, uuid, username, password_hash, email, phone, role, status, is_staff, plan_name, plan_months, price_cents, sub_slug, sub_token, sub_ticket_seed, assigned_nodes_json, expire_at, created_at, updated_at 
		FROM user WHERE LOWER(email) = LOWER(?)`, strings.TrimSpace(email))
	return a.scanUser(row)
}

func (a *AeroDB) scanUser(row *sql.Row) (*User, error) {
	var u User
	var statusInt, isStaffInt int
	var nodesJSON string
	var expStr, createdStr, updatedStr string
	err := row.Scan(&u.ID, &u.UUID, &u.Username, &u.PasswordHash, &u.Email, &u.Phone, &u.Role,
		&statusInt, &isStaffInt, &u.PlanName, &u.PlanMonths, &u.PriceCents, &u.SubSlug, &u.SubToken,
		&u.SubTicketSeed, &nodesJSON, &expStr, &createdStr, &updatedStr)
	if err != nil {
		return nil, errors.New("user not found")
	}
	u.Status = statusInt == 1
	u.IsStaff = isStaffInt == 1
	_ = json.Unmarshal([]byte(nodesJSON), &u.AssignedNodes)
	if u.AssignedNodes == nil {
		u.AssignedNodes = []string{}
	}
	if t, perr := time.Parse(time.RFC3339, expStr); perr == nil {
		u.ExpireAt = t
	}
	if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
		u.CreatedAt = t
	}
	if t, perr := time.Parse(time.RFC3339, updatedStr); perr == nil {
		u.UpdatedAt = t
	}
	return &u, nil
}

func (a *AeroDB) ListUsers(page, pageSize int) ([]User, int, error) {
	var total int
	_ = a.db.QueryRow(`SELECT count(*) FROM user`).Scan(&total)

	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	rows, err := a.db.Query(`SELECT id, uuid, username, password_hash, email, phone, role, status, is_staff, plan_name, plan_months, price_cents, sub_slug, sub_token, sub_ticket_seed, assigned_nodes_json, expire_at, created_at, updated_at 
		FROM user ORDER BY id DESC LIMIT ? OFFSET ?`, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []User
	for rows.Next() {
		var u User
		var statusInt, isStaffInt int
		var nodesJSON string
		var expStr, createdStr, updatedStr string
		if scanErr := rows.Scan(&u.ID, &u.UUID, &u.Username, &u.PasswordHash, &u.Email, &u.Phone, &u.Role,
			&statusInt, &isStaffInt, &u.PlanName, &u.PlanMonths, &u.PriceCents, &u.SubSlug, &u.SubToken,
			&u.SubTicketSeed, &nodesJSON, &expStr, &createdStr, &updatedStr); scanErr == nil {
			u.Status = statusInt == 1
			u.IsStaff = isStaffInt == 1
			_ = json.Unmarshal([]byte(nodesJSON), &u.AssignedNodes)
			if u.AssignedNodes == nil {
				u.AssignedNodes = []string{}
			}
			if t, perr := time.Parse(time.RFC3339, expStr); perr == nil {
				u.ExpireAt = t
			}
			if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
				u.CreatedAt = t
			}
			if t, perr := time.Parse(time.RFC3339, updatedStr); perr == nil {
				u.UpdatedAt = t
			}
			list = append(list, u)
		}
	}
	return list, total, nil
}

func (a *AeroDB) UpdateUser(id uint64, params UpdateUserParams) error {
	u, err := a.GetUser(id)
	if err != nil {
		return err
	}

	if params.Username != nil {
		newUsername := strings.TrimSpace(*params.Username)
		if newUsername != "" && newUsername != u.Username {
			if err := ValidateUsername(newUsername); err != nil {
				return err
			}
			var count int
			_ = a.db.QueryRow(`SELECT COUNT(*) FROM user WHERE LOWER(username) = LOWER(?) AND id != ?`, newUsername, id).Scan(&count)
			if count > 0 {
				return errors.New("用户名已被占用")
			}
			oldSlug := u.SubSlug
			u.Username = newUsername
			u.SubSlug = GenerateSubscriptionSlug(newUsername)
			if oldSlug != "" {
				_, _ = a.db.Exec(`UPDATE subscription SET sub_slug = ? WHERE sub_slug = ?`, u.SubSlug, oldSlug)
			}
		}
	}
	if params.Password != nil {
		newPwd := strings.TrimSpace(*params.Password)
		if newPwd != "" {
			if err := ValidatePassword(newPwd); err != nil {
				return err
			}
			u.PasswordHash = HashPassword(newPwd)
		}
	}
	if params.Phone != nil {
		u.Phone = *params.Phone
	}
	if params.Email != nil {
		u.Email = *params.Email
	}
	if params.Status != nil {
		u.Status = *params.Status
		statusInt := 0
		if u.Status {
			statusInt = 1
		}
		_, _ = a.db.Exec(`UPDATE subscription SET status = ? WHERE user_id = ?`, statusInt, id)
	}
	if params.IsStaff != nil {
		u.IsStaff = *params.IsStaff
	}
	if params.PlanName != nil {
		u.PlanName = *params.PlanName
	}
	if params.PlanMonths != nil {
		u.PlanMonths = *params.PlanMonths
	}
	if params.PriceCents != nil {
		u.PriceCents = *params.PriceCents
	}
	if params.AssignedNodes != nil {
		u.AssignedNodes = *params.AssignedNodes
	}
	if params.ExpireAt != nil {
		u.ExpireAt = *params.ExpireAt
	}

	nodesJSON, _ := json.Marshal(u.AssignedNodes)
	statusInt := 0
	if u.Status {
		statusInt = 1
	}
	isStaffInt := 0
	if u.IsStaff {
		isStaffInt = 1
	}
	nowStr := time.Now().Format(time.RFC3339)
	expStr := u.ExpireAt.Format(time.RFC3339)

	_, err = a.db.Exec(`UPDATE user SET username = ?, password_hash = ?, sub_slug = ?, phone = ?, email = ?, status = ?, is_staff = ?, plan_name = ?, plan_months = ?, price_cents = ?, assigned_nodes_json = ?, expire_at = ?, updated_at = ? WHERE id = ?`,
		u.Username, u.PasswordHash, u.SubSlug, u.Phone, u.Email, statusInt, isStaffInt, u.PlanName, u.PlanMonths, u.PriceCents, string(nodesJSON), expStr, nowStr, id)
	return err
}

func (a *AeroDB) DeleteUser(id uint64) error {
	u, _ := a.GetUser(id)
	uuid := ""
	slug := ""
	if u != nil {
		uuid = u.UUID
		slug = u.SubSlug
	}
	_, _ = a.db.Exec(`DELETE FROM subscription WHERE user_id = ? OR (user_uuid != '' AND user_uuid = ?) OR (sub_slug != '' AND sub_slug = ?)`, id, uuid, slug)
	_, _ = a.db.Exec(`DELETE FROM order_record WHERE user_id = ?`, id)
	_, _ = a.db.Exec(`DELETE FROM traffic WHERE user_id = ?`, id)
	_, err := a.db.Exec(`DELETE FROM user WHERE id = ?`, id)
	return err
}

func (a *AeroDB) SetStaff(id uint64, isStaff bool) error {
	val := 0
	if isStaff {
		val = 1
	}
	_, err := a.db.Exec(`UPDATE user SET is_staff = ?, updated_at = ? WHERE id = ?`, val, time.Now().Format(time.RFC3339), id)
	return err
}

func (a *AeroDB) SetPassword(id uint64, hash string) error {
	_, err := a.db.Exec(`UPDATE user SET password_hash = ?, updated_at = ? WHERE id = ?`, hash, time.Now().Format(time.RFC3339), id)
	return err
}

func (a *AeroDB) UpdateSubSlug(id uint64, slug string) error {
	_, err := a.db.Exec(`UPDATE user SET sub_slug = ?, updated_at = ? WHERE id = ?`, slug, time.Now().Format(time.RFC3339), id)
	return err
}

func (a *AeroDB) Renew(id uint64, planName string, months int32, priceCents int64) (*User, error) {
	u, err := a.GetUser(id)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	base := now
	if u.ExpireAt.After(now) {
		base = u.ExpireAt
	}
	u.ExpireAt = base.AddDate(0, int(months), 0)
	if planName != "" {
		u.PlanName = planName
	}
	if priceCents > 0 {
		u.PriceCents = priceCents
	}
	u.PlanMonths = months
	u.Status = true

	// Also renew user's subscriptions
	expStr := u.ExpireAt.Format(time.RFC3339)
	nowStr := now.Format(time.RFC3339)
	_, _ = a.db.Exec(`UPDATE subscription SET expire_at = ?, switch_status = 'on', status = 1, updated_at = ? WHERE user_id = ?`,
		expStr, nowStr, id)

	_ = a.UpdateUser(id, UpdateUserParams{
		PlanName:   &u.PlanName,
		PlanMonths: &u.PlanMonths,
		PriceCents: &u.PriceCents,
		ExpireAt:   &u.ExpireAt,
	})
	return u, nil
}

// ----------------------------------------------------------------------
// Subscription Operations
// ----------------------------------------------------------------------

func (a *AeroDB) CreateSubscription(sub *Subscription) error {
	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	expStr := sub.ExpireAt.Format(time.RFC3339)
	nodesJSON, _ := json.Marshal(sub.AssignedNodes)
	statusInt := 0
	if sub.Status {
		statusInt = 1
	}
	sw := sub.SwitchStatus
	if sw == "" {
		sw = "on"
	}

	_, err := a.db.Exec(`INSERT OR REPLACE INTO subscription 
		(sub_id, user_id, user_uuid, sub_slug, sub_token, sub_ticket_seed, plan_id, plan_name, assigned_nodes_json, limit_bytes, used_bytes, expire_at, switch_status, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sub.SubID, sub.UserID, sub.UserUUID, sub.SubSlug, sub.SubToken, sub.SubTicketSeed,
		sub.PlanName, string(nodesJSON), sub.LimitBytes, sub.UsedBytes, expStr, sw, statusInt, nowStr, nowStr)
	return err
}

func (a *AeroDB) GetSubscription(subID string) (*Subscription, error) {
	row := a.db.QueryRow(`SELECT sub_id, user_id, user_uuid, sub_slug, sub_token, sub_ticket_seed, plan_id, plan_name, assigned_nodes_json, limit_bytes, used_bytes, expire_at, switch_status, status, created_at, updated_at 
		FROM subscription WHERE sub_id = ?`, subID)
	return a.scanSubscription(row)
}

func (a *AeroDB) GetSubscriptionBySlug(slug string) (*Subscription, error) {
	row := a.db.QueryRow(`SELECT sub_id, user_id, user_uuid, sub_slug, sub_token, sub_ticket_seed, plan_id, plan_name, assigned_nodes_json, limit_bytes, used_bytes, expire_at, switch_status, status, created_at, updated_at 
		FROM subscription WHERE sub_slug = ?`, slug)
	return a.scanSubscription(row)
}

// GetSubscriptionByToken fetches a subscription by its sub_token.
func (a *AeroDB) GetSubscriptionByToken(token string) (*Subscription, error) {
	row := a.db.QueryRow(`SELECT sub_id, user_id, user_uuid, sub_slug, sub_token, sub_ticket_seed, plan_id, plan_name, assigned_nodes_json, limit_bytes, used_bytes, expire_at, switch_status, status, created_at, updated_at 
		FROM subscription WHERE sub_token = ?`, token)
	return a.scanSubscription(row)
}

// AddSubscriptionUsage atomically increments used_bytes by bytes.
// If limit_bytes > 0 and used_bytes >= limit_bytes, switch_status is set to "off" and circuitBroken is true.
func (a *AeroDB) AddSubscriptionUsage(token string, bytes int64) (*Subscription, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	tx, err := a.db.Begin()
	if err != nil {
		return nil, false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRow(`SELECT sub_id, user_id, user_uuid, sub_slug, sub_token, sub_ticket_seed, plan_id, plan_name, assigned_nodes_json, limit_bytes, used_bytes, expire_at, switch_status, status, created_at, updated_at 
		FROM subscription WHERE sub_token = ?`, token)
	sub, err := a.scanSubscription(row)
	if err != nil {
		return nil, false, err
	}

	newUsed := sub.UsedBytes + bytes
	nowStr := time.Now().Format(time.RFC3339)
	circuitBroken := false
	newSwitch := sub.SwitchStatus
	if sub.LimitBytes > 0 && newUsed >= sub.LimitBytes {
		newSwitch = "off"
		circuitBroken = true
	}

	_, err = tx.Exec(`UPDATE subscription SET used_bytes = ?, switch_status = ?, updated_at = ? WHERE sub_token = ?`,
		newUsed, newSwitch, nowStr, token)
	if err != nil {
		return nil, false, fmt.Errorf("update subscription usage: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit tx: %w", err)
	}

	sub.UsedBytes = newUsed
	sub.SwitchStatus = newSwitch
	return sub, circuitBroken, nil
}

// AddSubscriptionUsageBatch atomically increments usage for a batch of metering records in a single transaction.
// It checks limit_bytes for circuit breaking, sets switch_status to "off" if limit is reached,
// and returns a map indicating which tokens are revoked (e.g. over quota, expired, switched off, or not found).
func (a *AeroDB) AddSubscriptionUsageBatch(records []MeteringRecord) (map[string]bool, error) {
	if len(records) == 0 {
		return make(map[string]bool), nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Aggregate bytes by token
	deltas := make(map[string]int64)
	for _, rec := range records {
		tok := strings.TrimSpace(rec.Token)
		if tok == "" {
			continue
		}
		deltas[tok] += (rec.BytesUp + rec.BytesDown)
	}

	tx, err := a.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	revokedMap := make(map[string]bool)

	for tok, delta := range deltas {
		row := tx.QueryRow(`SELECT sub_id, user_id, user_uuid, sub_slug, sub_token, sub_ticket_seed, plan_id, plan_name, assigned_nodes_json, limit_bytes, used_bytes, expire_at, switch_status, status, created_at, updated_at 
			FROM subscription WHERE sub_token = ?`, tok)
		sub, err := a.scanSubscription(row)
		if err != nil {
			// Token not found in database -> revoked
			revokedMap[tok] = true
			continue
		}

		newUsed := sub.UsedBytes + delta
		newSwitch := sub.SwitchStatus
		isRevoked := false

		if sub.LimitBytes > 0 && newUsed >= sub.LimitBytes {
			newSwitch = "off"
			isRevoked = true
		}
		if !sub.ExpireAt.IsZero() && now.After(sub.ExpireAt) {
			isRevoked = true
		}
		if sub.SwitchStatus == "off" || !sub.Status {
			isRevoked = true
		}

		_, err = tx.Exec(`UPDATE subscription SET used_bytes = ?, switch_status = ?, updated_at = ? WHERE sub_token = ?`,
			newUsed, newSwitch, nowStr, tok)
		if err != nil {
			return nil, fmt.Errorf("batch update token %s: %w", tok, err)
		}

		revokedMap[tok] = isRevoked
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit batch tx: %w", err)
	}

	return revokedMap, nil
}

func (a *AeroDB) scanSubscription(row *sql.Row) (*Subscription, error) {
	var s Subscription
	var planID int
	var nodesJSON, expStr, sw, createdStr, updatedStr string
	var statusInt int
	err := row.Scan(&s.SubID, &s.UserID, &s.UserUUID, &s.SubSlug, &s.SubToken, &s.SubTicketSeed,
		&planID, &s.PlanName, &nodesJSON, &s.LimitBytes, &s.UsedBytes, &expStr, &sw, &statusInt, &createdStr, &updatedStr)
	if err != nil {
		return nil, errors.New("subscription not found")
	}
	s.Status = statusInt == 1
	s.SwitchStatus = sw
	_ = json.Unmarshal([]byte(nodesJSON), &s.AssignedNodes)
	if s.AssignedNodes == nil {
		s.AssignedNodes = []string{}
	}
	if t, perr := time.Parse(time.RFC3339, expStr); perr == nil {
		s.ExpireAt = t
	}
	if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
		s.CreatedAt = t
	}
	if t, perr := time.Parse(time.RFC3339, updatedStr); perr == nil {
		s.UpdatedAt = t
	}
	return &s, nil
}

func (a *AeroDB) ListSubscriptions(userID uint64) ([]*Subscription, error) {
	q := `SELECT sub_id, user_id, user_uuid, sub_slug, sub_token, sub_ticket_seed, plan_id, plan_name, assigned_nodes_json, limit_bytes, used_bytes, expire_at, switch_status, status, created_at, updated_at 
		FROM subscription`
	var args []any
	if userID > 0 {
		q += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	q += ` ORDER BY created_at DESC`

	rows, err := a.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Subscription
	for rows.Next() {
		var s Subscription
		var planID int
		var nodesJSON, expStr, sw, createdStr, updatedStr string
		var statusInt int
		if scanErr := rows.Scan(&s.SubID, &s.UserID, &s.UserUUID, &s.SubSlug, &s.SubToken, &s.SubTicketSeed,
			&planID, &s.PlanName, &nodesJSON, &s.LimitBytes, &s.UsedBytes, &expStr, &sw, &statusInt, &createdStr, &updatedStr); scanErr == nil {
			s.Status = statusInt == 1
			s.SwitchStatus = sw
			_ = json.Unmarshal([]byte(nodesJSON), &s.AssignedNodes)
			if s.AssignedNodes == nil {
				s.AssignedNodes = []string{}
			}
			if t, perr := time.Parse(time.RFC3339, expStr); perr == nil {
				s.ExpireAt = t
			}
			if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
				s.CreatedAt = t
			}
			if t, perr := time.Parse(time.RFC3339, updatedStr); perr == nil {
				s.UpdatedAt = t
			}
			list = append(list, &s)
		}
	}
	return list, nil
}

func (a *AeroDB) RenewSubscription(subID string, months int32, priceCents int64, planName string) (*Subscription, error) {
	sub, err := a.GetSubscription(subID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	base := now
	if sub.ExpireAt.After(now) {
		base = sub.ExpireAt
	}
	sub.ExpireAt = base.AddDate(0, int(months), 0)
	if planName != "" {
		sub.PlanName = planName
	}
	sub.Status = true
	sub.SwitchStatus = "on"

	expStr := sub.ExpireAt.Format(time.RFC3339)
	nowStr := now.Format(time.RFC3339)

	_, err = a.db.Exec(`UPDATE subscription SET expire_at = ?, plan_name = ?, switch_status = 'on', status = 1, updated_at = ? WHERE sub_id = ?`,
		expStr, sub.PlanName, nowStr, subID)
	if err != nil {
		return nil, err
	}
	return sub, nil
}

func (a *AeroDB) UpdateSubscription(subID string, status bool, assignedNodes []string) error {
	statusInt := 0
	if status {
		statusInt = 1
	}
	nodesJSON, _ := json.Marshal(assignedNodes)
	nowStr := time.Now().Format(time.RFC3339)
	_, err := a.db.Exec(`UPDATE subscription SET status = ?, assigned_nodes_json = ?, updated_at = ? WHERE sub_id = ?`,
		statusInt, string(nodesJSON), nowStr, subID)
	return err
}

// ----------------------------------------------------------------------
// Orders, Traffic & Plans
// ----------------------------------------------------------------------

func (a *AeroDB) CreateOrder(order *Order) error {
	now := time.Now().Format(time.RFC3339)
	nodesJSON, _ := json.Marshal(order.AssignedNodes)
	var paidStr *string
	if order.PaidAt != nil {
		p := order.PaidAt.Format(time.RFC3339)
		paidStr = &p
	}

	_, err := a.db.Exec(`INSERT OR REPLACE INTO order_record 
		(order_no, user_id, plan_id, plan_name, assigned_nodes_json, amount_cents, pay_channel, status, created_at, paid_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		order.OrderNo, order.UserID, order.PlanID, order.PlanName, string(nodesJSON), order.AmountCents, order.PayChannel, order.Status, now, paidStr)
	if err != nil {
		return err
	}

	// Synchronize to aeropay.db
	if a.payDB != nil {
		_ = a.payDB.RecordIncome(order)
	}
	return nil
}

func (a *AeroDB) ListOrders(userID uint64) ([]Order, error) {
	q := `SELECT order_no, user_id, plan_id, plan_name, assigned_nodes_json, amount_cents, pay_channel, status, created_at, paid_at FROM order_record`
	var args []any
	if userID > 0 {
		q += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	q += ` ORDER BY created_at DESC`

	rows, err := a.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Order
	for rows.Next() {
		var o Order
		var nodesJSON string
		var createdStr string
		var paidStr sql.NullString
		if err := rows.Scan(&o.OrderNo, &o.UserID, &o.PlanID, &o.PlanName, &nodesJSON, &o.AmountCents, &o.PayChannel, &o.Status, &createdStr, &paidStr); err == nil {
			_ = json.Unmarshal([]byte(nodesJSON), &o.AssignedNodes)
			if o.AssignedNodes == nil {
				o.AssignedNodes = []string{}
			}
			if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
				o.CreatedAt = t
			}
			if paidStr.Valid && paidStr.String != "" {
				if t, perr := time.Parse(time.RFC3339, paidStr.String); perr == nil {
					o.PaidAt = &t
				}
			}
			list = append(list, o)
		}
	}
	return list, nil
}

func (a *AeroDB) UpdateOrderStatus(orderNo string, status string) error {
	nowStr := time.Now().Format(time.RFC3339)
	var paidStr *string
	if status == "completed" {
		paidStr = &nowStr
	}
	_, err := a.db.Exec(`UPDATE order_record SET status = ?, paid_at = ? WHERE order_no = ?`, status, paidStr, orderNo)
	return err
}

func (a *AeroDB) GetTraffic(id uint64) (*TrafficStats, error) {
	row := a.db.QueryRow(`SELECT user_id, used_bytes, limit_bytes, is_connected, updated_at FROM traffic WHERE user_id = ?`, id)
	var ts TrafficStats
	var isConn int
	var updatedStr string
	err := row.Scan(&ts.UserID, &ts.UsedBytes, &ts.LimitBytes, &isConn, &updatedStr)
	if err != nil {
		return &TrafficStats{
			UserID:      id,
			UsedBytes:   0,
			LimitBytes:  107374182400,
			IsConnected: false,
			UpdatedAt:   time.Now(),
		}, nil
	}
	ts.IsConnected = isConn == 1
	if t, perr := time.Parse(time.RFC3339, updatedStr); perr == nil {
		ts.UpdatedAt = t
	}
	return &ts, nil
}

func (a *AeroDB) UpdateTraffic(id uint64, usedBytes, limitBytes int64) error {
	nowStr := time.Now().Format(time.RFC3339)
	ts, _ := a.GetTraffic(id)
	if usedBytes >= 0 {
		ts.UsedBytes = usedBytes
	}
	if limitBytes > 0 || limitBytes == -1 {
		ts.LimitBytes = limitBytes
	}
	_, err := a.db.Exec(`INSERT OR REPLACE INTO traffic (user_id, used_bytes, limit_bytes, is_connected, updated_at)
		VALUES (?, ?, ?, ?, ?)`, id, ts.UsedBytes, ts.LimitBytes, 0, nowStr)
	return err
}

func (a *AeroDB) ListPlans() ([]Plan, error) {
	rows, err := a.db.Query(`SELECT id, name, period_type, period_value, price_cents, traffic_bytes, assigned_nodes_json, status, sort_order, created_at, updated_at FROM plan ORDER BY sort_order ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Plan
	for rows.Next() {
		var p Plan
		var statusInt int
		var nodesJSON, createdStr, updatedStr string
		if scanErr := rows.Scan(&p.ID, &p.Name, &p.PeriodType, &p.PeriodValue, &p.PriceCents, &p.TrafficBytes, &nodesJSON, &statusInt, &p.SortOrder, &createdStr, &updatedStr); scanErr == nil {
			p.Status = statusInt == 1
			p.DurationMonths = p.PeriodValue
			_ = json.Unmarshal([]byte(nodesJSON), &p.AssignedNodes)
			if p.AssignedNodes == nil {
				p.AssignedNodes = []string{}
			}
			if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
				p.CreatedAt = t
			}
			out = append(out, p)
		}
	}
	return out, nil
}

func (a *AeroDB) CreatePlan(p *Plan) (*Plan, error) {
	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	nodesJSON, _ := json.Marshal(p.AssignedNodes)
	statusInt := 0
	if p.Status {
		statusInt = 1
	}
	periodType := p.PeriodType
	if periodType == "" {
		periodType = "month"
	}
	periodVal := p.PeriodValue
	if periodVal <= 0 {
		if p.DurationMonths > 0 {
			periodVal = p.DurationMonths
		} else {
			periodVal = 1
		}
	}
	res, err := a.db.Exec(`INSERT INTO plan 
		(name, period_type, period_value, price_cents, traffic_bytes, assigned_nodes_json, status, sort_order, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, periodType, periodVal, p.PriceCents, p.TrafficBytes, string(nodesJSON), statusInt, p.SortOrder, nowStr, nowStr)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	p.ID = id
	p.DurationMonths = periodVal
	p.CreatedAt = now
	p.UpdatedAt = now
	return p, nil
}

func (a *AeroDB) GetPlan(id int64) (*Plan, error) {
	row := a.db.QueryRow(`SELECT id, name, period_type, period_value, price_cents, traffic_bytes, assigned_nodes_json, status, sort_order, created_at, updated_at FROM plan WHERE id = ?`, id)
	var p Plan
	var statusInt int
	var nodesJSON, createdStr, updatedStr string
	if err := row.Scan(&p.ID, &p.Name, &p.PeriodType, &p.PeriodValue, &p.PriceCents, &p.TrafficBytes, &nodesJSON, &statusInt, &p.SortOrder, &createdStr, &updatedStr); err != nil {
		return nil, errors.New("plan not found")
	}
	p.Status = statusInt == 1
	p.DurationMonths = p.PeriodValue
	_ = json.Unmarshal([]byte(nodesJSON), &p.AssignedNodes)
	if p.AssignedNodes == nil {
		p.AssignedNodes = []string{}
	}
	if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
		p.CreatedAt = t
	}
	if t, perr := time.Parse(time.RFC3339, updatedStr); perr == nil {
		p.UpdatedAt = t
	}
	return &p, nil
}

func (a *AeroDB) UpdatePlan(id int64, name *string, price *int64, traffic *int64, status *bool, nodes []string) error {
	p, err := a.GetPlan(id)
	if err != nil {
		return err
	}
	if name != nil {
		p.Name = *name
	}
	if price != nil {
		p.PriceCents = *price
	}
	if traffic != nil {
		p.TrafficBytes = *traffic
	}
	if status != nil {
		p.Status = *status
	}
	if nodes != nil {
		p.AssignedNodes = nodes
	}
	statusInt := 0
	if p.Status {
		statusInt = 1
	}
	nodesJSON, _ := json.Marshal(p.AssignedNodes)
	nowStr := time.Now().Format(time.RFC3339)
	_, err = a.db.Exec(`UPDATE plan SET name = ?, price_cents = ?, traffic_bytes = ?, assigned_nodes_json = ?, status = ?, updated_at = ? WHERE id = ?`,
		p.Name, p.PriceCents, p.TrafficBytes, string(nodesJSON), statusInt, nowStr, id)
	return err
}

func (a *AeroDB) DeletePlan(id int64) error {
	_, err := a.db.Exec(`DELETE FROM plan WHERE id = ?`, id)
	return err
}

func (a *AeroDB) DeleteSubscription(subID string) error {
	sub, _ := a.GetSubscription(subID)
	if sub != nil {
		nowStr := time.Now().Format(time.RFC3339)
		_, _ = a.db.Exec(`UPDATE user SET sub_slug = '', updated_at = ? WHERE id = ? AND sub_slug = ?`, nowStr, sub.UserID, sub.SubSlug)
	}
	_, err := a.db.Exec(`DELETE FROM subscription WHERE sub_id = ?`, subID)
	return err
}

func (a *AeroDB) UpdateSubscriptionSwitch(subID string, switchStatus string) error {
	nowStr := time.Now().Format(time.RFC3339)
	_, err := a.db.Exec(`UPDATE subscription SET switch_status = ?, updated_at = ? WHERE sub_id = ?`, switchStatus, nowStr, subID)
	return err
}
