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
	"time"

	_ "modernc.org/sqlite"
)

// C6 计量拉取（api/edge-public.yaml，ADR-0001：sub 只读 edge，edge 不推送）。
// 每 60 秒按游标读取各节点 /v1/usage；记录是 (node_id, uid, period_start) 的累计值，按该三元组覆盖写入，
// 重复读取幂等。游标早于保留期（410）或节点标识变化时从头重读。只保存 iss=sub 的记录。
// 只轮询已登记计量只读密钥的节点（节点开启 usage_api 后经 SSH 只读回读）。

const (
	usagePollInterval  = 60 * time.Second // 契约 x-aero-decisions
	usagePollTimeout   = 10 * time.Second // 单次请求上限（L0 §8.1）
	usagePollMaxPages  = 50               // 单轮每节点最多页数（50×1000 条），其余下一轮继续
	usagePageLimit     = 1000
	usagePageBodyLimit = 4 << 20
)

// UsageCollector 拉取并汇总各节点的计量记录。
type UsageCollector struct {
	db     *sql.DB
	eps    *EndpointStore
	client *http.Client
}

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
);`); err != nil {
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
	return &UsageCollector{db: db, eps: eps, client: &http.Client{Timeout: usagePollTimeout, Transport: tr}}, nil
}

// Close 关闭数据库。
func (c *UsageCollector) Close() error { return c.db.Close() }

// Run 每 60 秒轮询一次，直到 ctx 结束。节点逐个串行拉取，协程数恒为 1。
func (c *UsageCollector) Run(ctx context.Context) {
	t := time.NewTicker(usagePollInterval)
	defer t.Stop()
	for {
		c.PollOnce(ctx)
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
		if !ep.Installed || ep.MeteringKey == "" || ep.Host == "" || ep.Port <= 0 {
			continue
		}
		if err := c.pollNode(ctx, ep); err != nil && ctx.Err() == nil {
			log.Printf("[USAGE] poll vps %d (%s): %v", ep.VPSID, ep.Host, err)
		}
	}
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
