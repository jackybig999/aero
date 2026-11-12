package sub

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// C6 计量拉取（api/edge-public.yaml，ADR-0001：sub 只读 edge，edge 不推送）。
// 每 60 秒按游标读取各节点 /v1/usage；记录是 (node_id, uid, period_start) 的累计值，按该三元组覆盖写入，
// 重复读取幂等。游标早于保留期（410）或节点标识变化时从头重读。只保存 iss=sub 的记录。
// 计量只读密钥经 C13 GET /admin/v1/usage-api 取得（节点开启 usage_api 后才有）。
//
// 汇总（用户决定 2026-11-12）：按自然月（UTC，每月 1 日清零）把该用户在所有节点上的上下行之和写入
// traffic.used_bytes。每轮只重算本轮有变化的用户；跨月时把上月写过的用户清零。

const (
	usagePollInterval  = 60 * time.Second // 契约 x-aero-decisions
	usagePollTimeout   = 10 * time.Second // 单次请求上限（L0 §8.1）
	usagePollMaxPages  = 50               // 单轮每节点最多页数（50×1000 条），其余下一轮继续
	usagePageLimit     = 1000
	usagePageBodyLimit = 4 << 20
	usageKeepDays      = 400 // 中台保留约 13 个月，按天清理
)

// UsageCollector 拉取并汇总各节点的计量记录。
type UsageCollector struct {
	db     *sql.DB
	eps    *EndpointStore
	users  UserStore // 汇总目标；nil 时只采集不汇总
	client *http.Client
	now    func() time.Time
}

// SetUserStore 设置汇总目标（traffic.used_bytes）。须在 Run 之前调用。
func (c *UsageCollector) SetUserStore(u UserStore) { c.users = u }

// OpenUsageCollector 打开 path（独立 SQLite，不与 aero.db 共享表结构）。
func OpenUsageCollector(path string, eps *EndpointStore) (*UsageCollector, error) {
	dsn := "file:" + url.PathEscape(path) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open usage db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS node_usage (
	node_id      TEXT NOT NULL,
	uid          TEXT NOT NULL,
	period_start INTEGER NOT NULL,
	bytes_up     INTEGER NOT NULL,
	bytes_down   INTEGER NOT NULL,
	final        INTEGER NOT NULL,
	PRIMARY KEY (node_id, uid, period_start)
);
CREATE INDEX IF NOT EXISTS node_usage_uid ON node_usage (uid, period_start);
CREATE TABLE IF NOT EXISTS node_cursor (
	vps_id  INTEGER PRIMARY KEY,
	node_id TEXT NOT NULL,
	cursor  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS uid_dirty (uid TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS user_month (user_id INTEGER PRIMARY KEY, month_start INTEGER NOT NULL);`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate usage db: %w", err)
	}
	// 节点使用 Let's Encrypt 证书：严格校验，计量密钥不得发给未验证的对端。
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     2 * usagePollInterval,
	}
	return &UsageCollector{db: db, eps: eps, client: &http.Client{Timeout: usagePollTimeout, Transport: tr}, now: time.Now}, nil
}

// Close 关闭数据库。
func (c *UsageCollector) Close() error { return c.db.Close() }

// Run 每 60 秒轮询一次，直到 ctx 结束。节点逐个串行拉取，协程数恒为 1。
func (c *UsageCollector) Run(ctx context.Context) {
	t := time.NewTicker(usagePollInterval)
	defer t.Stop()
	var lastPrune time.Time
	for {
		c.PollOnce(ctx)
		if err := c.ApplyMonthly(); err != nil {
			log.Printf("[USAGE] apply monthly usage: %v", err)
		}
		if now := c.now(); now.Sub(lastPrune) > 24*time.Hour {
			if _, err := c.db.Exec(`DELETE FROM node_usage WHERE period_start < ?`, now.AddDate(0, 0, -usageKeepDays).Unix()); err != nil {
				log.Printf("[USAGE] prune: %v", err)
			}
			lastPrune = now
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PollOnce 拉取所有已登记计量密钥的节点；单个节点失败只记录日志，不影响其他节点。
func (c *UsageCollector) PollOnce(ctx context.Context) {
	for _, ep := range c.eps.List() {
		if !ep.Installed || ep.Host == "" || ep.Port <= 0 {
			continue
		}
		if ep.MeteringKey == "" { // 节点开启计量后经 C13 取得只读密钥
			if ep.MeteringKey = c.fetchMeteringKey(ctx, ep); ep.MeteringKey == "" {
				continue
			}
		}
		if err := c.pollNode(ctx, ep); err != nil && ctx.Err() == nil {
			log.Printf("[USAGE] poll vps %d (%s): %v", ep.VPSID, ep.Host, err)
		}
	}
}

// fetchMeteringKey 经 C13 读取节点的计量只读密钥并登记；节点未开启计量或接口不可用时返回空。
func (c *UsageCollector) fetchMeteringKey(ctx context.Context, ep EndpointInfo) string {
	if ep.AdminKey == "" {
		return ""
	}
	var us edgeUsageState
	if err := edgeAPI(ctx, ep, http.MethodGet, "/admin/v1/usage-api", nil, &us); err != nil || !us.Enabled || us.MeteringKey == "" {
		return ""
	}
	if err := c.eps.SetMeteringKey(ep.VPSID, us.MeteringKey); err != nil {
		log.Printf("[USAGE] store metering key for vps %d: %v", ep.VPSID, err)
	}
	return us.MeteringKey
}

type usagePageResp struct {
	NodeID  string `json:"node_id"`
	Records []struct {
		Seq         int64  `json:"seq"`
		UID         string `json:"uid"`
		Iss         string `json:"iss"`
		PeriodStart int64  `json:"period_start"`
		BytesUp     int64  `json:"bytes_up"`
		BytesDown   int64  `json:"bytes_down"`
		Final       bool   `json:"final"`
	} `json:"records"`
	NextCursor string `json:"next_cursor"`
}

var errUsageCursorGone = errors.New("cursor expired")

func (c *UsageCollector) pollNode(ctx context.Context, ep EndpointInfo) error {
	nodeID, cursor, err := c.cursor(ep.VPSID)
	if err != nil {
		return err
	}
	for page := 0; page < usagePollMaxPages; page++ {
		resp, err := c.fetch(ctx, ep, cursor)
		if errors.Is(err, errUsageCursorGone) {
			cursor = "" // 从头重读：覆盖写入，幂等
			continue
		}
		if err != nil {
			return err
		}
		if resp.NodeID == "" {
			return fmt.Errorf("response without node_id")
		}
		if nodeID != "" && resp.NodeID != nodeID && cursor != "" {
			nodeID, cursor = resp.NodeID, "" // 节点重装（新的 seq 序列）：从头读
			continue
		}
		nodeID = resp.NodeID
		if err := c.store(ep.VPSID, resp); err != nil {
			return err
		}
		if len(resp.Records) == 0 || resp.NextCursor == cursor {
			return nil
		}
		cursor = resp.NextCursor
	}
	return nil
}

func (c *UsageCollector) fetch(ctx context.Context, ep EndpointInfo, cursor string) (*usagePageResp, error) {
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)), Path: "/v1/usage"}
	q := url.Values{"limit": {strconv.Itoa(usagePageLimit)}}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ep.MeteringKey)
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, usagePageBodyLimit))
	if err != nil {
		return nil, err
	}
	switch {
	case res.StatusCode == http.StatusGone:
		return nil, errUsageCursorGone
	case res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json":
		// 密钥错误或接口未开启时节点返回伪装站（200 text/html），不能当作数据
		return nil, fmt.Errorf("http %d (%s)", res.StatusCode, res.Header.Get("Content-Type"))
	}
	var page usagePageResp
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode usage page: %w", err)
	}
	return &page, nil
}

func (c *UsageCollector) cursor(vpsID uint64) (nodeID, cursor string, err error) {
	err = c.db.QueryRow(`SELECT node_id, cursor FROM node_cursor WHERE vps_id = ?`, vpsID).Scan(&nodeID, &cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return nodeID, cursor, err
}

// store 在一个事务中覆盖写入本页记录并推进游标。
func (c *UsageCollector) store(vpsID uint64, page *usagePageResp) error {
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, r := range page.Records {
		if r.Iss != "sub" || r.UID == "" || r.BytesUp < 0 || r.BytesDown < 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO node_usage (node_id, uid, period_start, bytes_up, bytes_down, final) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (node_id, uid, period_start) DO UPDATE SET bytes_up = excluded.bytes_up, bytes_down = excluded.bytes_down, final = excluded.final`,
			page.NodeID, r.UID, r.PeriodStart, r.BytesUp, r.BytesDown, r.Final); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO uid_dirty (uid) VALUES (?)`, r.UID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO node_cursor (vps_id, node_id, cursor) VALUES (?, ?, ?)
		ON CONFLICT (vps_id) DO UPDATE SET node_id = excluded.node_id, cursor = excluded.cursor`, vpsID, page.NodeID, page.NextCursor); err != nil {
		return err
	}
	return tx.Commit()
}

// UsageSince 返回 uid 自 since（含）起在所有节点上的累计上下行字节。
func (c *UsageCollector) UsageSince(uid string, since time.Time) (up, down int64, err error) {
	err = c.db.QueryRow(`SELECT COALESCE(SUM(bytes_up), 0), COALESCE(SUM(bytes_down), 0) FROM node_usage WHERE uid = ? AND period_start >= ?`,
		uid, since.Unix()).Scan(&up, &down)
	return up, down, err
}

// monthStart 返回 t 所在自然月（UTC）的起点。
func monthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// ApplyMonthly 把本月（UTC）各用户在所有节点上的用量写入 traffic.used_bytes：
// 先把上月写过、本月尚无变化的用户清零，再重算本轮有变化的用户。失败的用户留待下一轮。
func (c *UsageCollector) ApplyMonthly() error {
	if c.users == nil {
		return nil
	}
	month := monthStart(c.now())
	var errs []error
	stale, err := c.queryInts(`SELECT user_id FROM user_month WHERE month_start < ?`, month.Unix())
	if err != nil {
		return err
	}
	for _, id := range stale {
		if err := c.users.UpdateTraffic(uint64(id), 0, 0); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := c.db.Exec(`UPDATE user_month SET month_start = ? WHERE user_id = ?`, month.Unix(), id); err != nil {
			errs = append(errs, err)
		}
	}
	dirty, err := c.queryStrings(`SELECT uid FROM uid_dirty`)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, uid := range dirty {
		if err := c.applyUID(uid, month); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", uid, err))
			continue
		}
		if _, err := c.db.Exec(`DELETE FROM uid_dirty WHERE uid = ?`, uid); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// applyUID 写入一个 uid 的本月用量；uid 不对应任何现有用户（已删除或非本中台签发）时直接丢弃。
func (c *UsageCollector) applyUID(uid string, month time.Time) error {
	id, ok := userIDFromTokenUID(uid)
	if !ok {
		return nil
	}
	u, err := c.users.GetUser(id)
	if err != nil || u == nil || tokenUID(u) != uid {
		return nil
	}
	up, down, err := c.UsageSince(uid, month)
	if err != nil {
		return err
	}
	if err := c.users.UpdateTraffic(id, up+down, 0); err != nil {
		return err
	}
	_, err = c.db.Exec(`INSERT INTO user_month (user_id, month_start) VALUES (?, ?)
		ON CONFLICT (user_id) DO UPDATE SET month_start = excluded.month_start`, id, month.Unix())
	return err
}

// userIDFromTokenUID 从 tokenUID 的末段取出用户 ID（调用方须再以 tokenUID(user) == uid 核对）。
func userIDFromTokenUID(uid string) (uint64, bool) {
	i := strings.LastIndexByte(uid, '-')
	if i < 0 {
		return 0, false
	}
	id, err := strconv.ParseUint(uid[i+1:], 10, 64)
	return id, err == nil && id > 0
}

func (c *UsageCollector) queryInts(q string, args ...any) ([]int64, error) {
	rows, err := c.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (c *UsageCollector) queryStrings(q string, args ...any) ([]string, error) {
	rows, err := c.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
