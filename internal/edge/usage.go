package edge

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// C6 计量（api/edge-public.yaml）：按 uid、按小时累计 IP 层字节。
//
// 热路径：每个会话开始时取得该 uid 的 usageCell，之后每个报文只做原子加法；后台每分钟把计数原子取出并
// 写入 SQLite。每个 (uid, 小时) 只存一行，数值变化时分配新的单调序号，游标“seq > cursor”即可取到全部
// 有变化的小时（消费方按三元组覆盖写入）；逐次追加会使 90 天保留期累积上千万行。
// 只计量签名 token（有 uid）；过渡期内的不透明 token 不计量（sub 只处理 iss=sub 的记录）。

const (
	usageRetention     = 90 * 24 * time.Hour // PROJECT_RULES §6.11
	usageFlushInterval = time.Minute
	usageSchemaVersion = 1
	usagePageMax       = 1000
)

// ErrUsageCursorExpired 表示游标早于保留期，消费方需从头读取（HTTP 410）。
var ErrUsageCursorExpired = errors.New("usage cursor older than retention")

// usageCell 是某 uid 的未落盘计数。
type usageCell struct {
	uid, iss string
	up, down atomic.Int64
}

// Add 记录一次传输（热路径，原子操作）；cell 为 nil（不计量的 token）时无操作。
func (c *usageCell) Add(up, down int64) {
	if c == nil {
		return
	}
	if up > 0 {
		c.up.Add(up)
	}
	if down > 0 {
		c.down.Add(down)
	}
}

// UsageMeter 汇总各 uid 的计数并定期落盘。
type UsageMeter struct {
	store *usageStore
	mu    sync.Mutex
	cells map[string]*usageCell // uid → cell
	now   func() time.Time
}

// OpenUsageMeter 打开 dataDir/usage.db。
func OpenUsageMeter(path string) (*UsageMeter, error) {
	st, err := openUsageStore(path)
	if err != nil {
		return nil, err
	}
	return &UsageMeter{store: st, cells: make(map[string]*usageCell), now: time.Now}, nil
}

// Cell 返回 token 对应 uid 的计数单元；不透明 token 或无法解析时返回 nil（不计量）。
// token 已在鉴权时验签，此处只读取载荷中的 uid 与 iss。
func (m *UsageMeter) Cell(token string) *usageCell {
	if m == nil {
		return nil
	}
	uid, iss, ok := tokenUIDUnverified(token)
	if !ok {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cells[uid]
	if !ok {
		c = &usageCell{uid: uid, iss: iss}
		m.cells[uid] = c
	}
	return c
}

// Flush 把全部单元的计数写入当前小时（取出并清零，原子）。写入失败时把计数加回，下次重试。
func (m *UsageMeter) Flush() error {
	if m == nil {
		return nil
	}
	period := m.now().UTC().Truncate(time.Hour).Unix()
	m.mu.Lock()
	cells := make([]*usageCell, 0, len(m.cells))
	for _, c := range m.cells {
		cells = append(cells, c)
	}
	m.mu.Unlock()
	var errs []error
	for _, c := range cells {
		up, down := c.up.Swap(0), c.down.Swap(0)
		if up == 0 && down == 0 {
			continue
		}
		if err := m.store.add(c.uid, c.iss, period, up, down); err != nil {
			c.Add(up, down)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Run 每分钟落盘并每天清理过期记录，直到 stop 关闭；退出前再落盘一次。
func (m *UsageMeter) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(usageFlushInterval)
	defer ticker.Stop()
	lastPrune := time.Time{}
	for {
		select {
		case <-stop:
			_ = m.Flush()
			return
		case <-ticker.C:
			_ = m.Flush()
			if now := m.now(); now.Sub(lastPrune) > 24*time.Hour {
				_ = m.store.prune(now.Add(-usageRetention).Unix())
				lastPrune = now
			}
		}
	}
}

// UsageRecord 是 C6 记录。
type UsageRecord struct {
	Seq         int64  `json:"seq"`
	UID         string `json:"uid"`
	Iss         string `json:"iss,omitempty"`
	PeriodStart int64  `json:"period_start"`
	BytesUp     int64  `json:"bytes_up"`
	BytesDown   int64  `json:"bytes_down"`
	Final       bool   `json:"final"`
}

// Page 返回 seq > cursor 的记录（至多 limit 条）与下一页游标；游标早于保留期返回 ErrUsageCursorExpired。
func (m *UsageMeter) Page(cursor string, limit int) ([]UsageRecord, string, error) {
	var after int64
	if cursor != "" {
		v, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || v < 0 {
			return nil, "", fmt.Errorf("invalid cursor")
		}
		after = v
	}
	if limit <= 0 || limit > usagePageMax {
		limit = 500
	}
	if after > 0 { // 游标之后的记录已被清理：消费方须从头读取
		pruned, err := m.store.prunedBelow()
		if err != nil {
			return nil, "", err
		}
		if after < pruned {
			return nil, "", ErrUsageCursorExpired
		}
	}
	recs, err := m.store.page(after, limit)
	if err != nil {
		return nil, "", err
	}
	// 小时结束且已过一个落盘周期，之后不会再出现更大的 seq
	finalBefore := m.now().UTC().Truncate(time.Hour).Unix()
	if m.now().Sub(m.now().Truncate(time.Hour)) < usageFlushInterval {
		finalBefore -= 3600
	}
	next := cursor
	if next == "" {
		next = "0"
	}
	for i := range recs {
		recs[i].Final = recs[i].PeriodStart < finalBefore
		next = strconv.FormatInt(recs[i].Seq, 10)
	}
	return recs, next, nil
}

// Close 落盘并关闭数据库。
func (m *UsageMeter) Close() error {
	if m == nil {
		return nil
	}
	return errors.Join(m.Flush(), m.store.close())
}

// tokenUIDUnverified 读取 aero1 载荷中的 uid 与 iss（调用方保证 token 已验签）。
func tokenUIDUnverified(token string) (uid, iss string, ok bool) {
	rest, found := strings.CutPrefix(token, tokenPrefix)
	if !found {
		return "", "", false
	}
	payload, _, found := strings.Cut(rest, ".")
	if !found {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", false
	}
	var c struct {
		UID string `json:"uid"`
		Iss string `json:"iss"`
	}
	if json.Unmarshal(raw, &c) != nil || !uidPattern.MatchString(c.UID) {
		return "", "", false
	}
	return c.UID, c.Iss, true
}

// ---- 存储 ----

type usageStore struct {
	db *sql.DB // 单写连接（PROJECT_RULES §6.10）
}

func openUsageStore(path string) (*usageStore, error) {
	dsn := "file:" + url.PathEscape(path) + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open usage store: %w", err)
	}
	db.SetMaxOpenConns(1)
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read usage schema version: %w", err)
	}
	if version > usageSchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf("usage store schema %d is newer than supported %d", version, usageSchemaVersion)
	}
	if version < 1 {
		if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS usage (
	uid          TEXT NOT NULL,
	iss          TEXT NOT NULL,
	period_start INTEGER NOT NULL,
	bytes_up     INTEGER NOT NULL CHECK (bytes_up >= 0),
	bytes_down   INTEGER NOT NULL CHECK (bytes_down >= 0),
	seq          INTEGER NOT NULL UNIQUE,
	PRIMARY KEY (uid, period_start)
);
CREATE TABLE IF NOT EXISTS usage_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
PRAGMA user_version = 1;`); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate usage store: %w", err)
		}
	}
	return &usageStore{db: db}, nil
}

// add 累加 (uid, period) 的字节并分配新的 seq（单写连接 + 事务，seq 单调）。
func (s *usageStore) add(uid, iss string, period, up, down int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var next int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) + 1 FROM usage`).Scan(&next); err != nil {
		return err
	}
	if pruned, err := prunedBelowTx(tx); err != nil {
		return err
	} else if next <= pruned {
		next = pruned + 1 // 清理后 MAX(seq) 可能回退，seq 不得复用
	}
	if _, err := tx.Exec(`INSERT INTO usage (uid, iss, period_start, bytes_up, bytes_down, seq) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (uid, period_start) DO UPDATE SET bytes_up = bytes_up + excluded.bytes_up,
			bytes_down = bytes_down + excluded.bytes_down, seq = excluded.seq`, uid, iss, period, up, down, next); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *usageStore) page(after int64, limit int) ([]UsageRecord, error) {
	rows, err := s.db.Query(`SELECT seq, uid, iss, period_start, bytes_up, bytes_down FROM usage WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UsageRecord
	for rows.Next() {
		var r UsageRecord
		if err := rows.Scan(&r.Seq, &r.UID, &r.Iss, &r.PeriodStart, &r.BytesUp, &r.BytesDown); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// prune 删除早于 before 的小时，并记录被删除的最大 seq（更早的游标须返回 410）。
func (s *usageStore) prune(before int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var maxDeleted sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(seq) FROM usage WHERE period_start < ?`, before).Scan(&maxDeleted); err != nil {
		return err
	}
	if !maxDeleted.Valid {
		return nil
	}
	if _, err := tx.Exec(`DELETE FROM usage WHERE period_start < ?`, before); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO usage_meta (k, v) VALUES ('pruned_below', ?) ON CONFLICT (k) DO UPDATE SET v = MAX(v, excluded.v)`, maxDeleted.Int64); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *usageStore) prunedBelow() (int64, error) {
	var v sql.NullInt64
	err := s.db.QueryRow(`SELECT v FROM usage_meta WHERE k = 'pruned_below'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v.Int64, err
}

func prunedBelowTx(tx *sql.Tx) (int64, error) {
	var v sql.NullInt64
	err := tx.QueryRow(`SELECT v FROM usage_meta WHERE k = 'pruned_below'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v.Int64, err
}

func (s *usageStore) close() error { return s.db.Close() }
