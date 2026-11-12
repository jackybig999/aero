package edge

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// C6 只读接口（api/edge-public.yaml）：GET /v1/usage、GET /v1/status。
// 只认计量只读密钥（与管理密钥、用户 token 互不复用）；未鉴权或密钥错误时返回 false，由调用方按伪装站响应，
// 不暴露接口存在（EDGE_METERING_UNAUTHORIZED）。持有密钥只能读取，不能修改 edge 任何状态。

const usageAPIRatePerMinute = 60 // 契约：每个密钥 60 次/分钟

// nodeStatus 对应契约 NodeStatus。
type nodeStatus struct {
	NodeID         string       `json:"node_id"`
	Version        string       `json:"version"`
	Ready          bool         `json:"ready"`
	ActiveSessions int          `json:"active_sessions"`
	SessionsByUID  []uidSession `json:"sessions_by_uid,omitempty"`
}

type uidSession struct {
	UID      string `json:"uid"`
	Sessions int    `json:"sessions"`
}

// usagePage 对应契约 UsagePage。
type usagePage struct {
	NodeID     string        `json:"node_id"`
	Records    []UsageRecord `json:"records"`
	NextCursor string        `json:"next_cursor"`
}

type usageAPI struct {
	meter  *UsageMeter
	key    []byte
	nodeID string
	status func() nodeStatus // 由 Server 提供（就绪状态、在线会话）
	now    func() time.Time

	mu          sync.Mutex
	windowStart time.Time
	count       int
}

func newUsageAPI(meter *UsageMeter, key, nodeID string, status func() nodeStatus) *usageAPI {
	return &usageAPI{meter: meter, key: []byte(key), nodeID: nodeID, status: status, now: time.Now}
}

// TryServe 处理 /v1/usage 与 /v1/status；返回 false 表示交给伪装站。
func (a *usageAPI) TryServe(w http.ResponseWriter, r *http.Request) bool {
	if a == nil || len(a.key) == 0 || (r.URL.Path != "/v1/usage" && r.URL.Path != "/v1/status") {
		return false
	}
	tok, ok := bearerToken(r)
	if !ok || r.Method != http.MethodGet || subtle.ConstantTimeCompare([]byte(tok), a.key) != 1 {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if retry := a.take(); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeProblem(w, http.StatusTooManyRequests, "EDGE_RATE_LIMITED", "rate limited")
		return true
	}
	if r.URL.Path == "/v1/status" {
		st := a.status()
		st.NodeID = a.nodeID
		writeAPIJSON(w, st)
		return true
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit")) // 缺省或非法时 Page 取默认 500
	recs, next, err := a.meter.Page(q.Get("cursor"), limit)
	switch {
	case errors.Is(err, ErrUsageCursorExpired) || errors.Is(err, errUsageCursorInvalid):
		writeProblem(w, http.StatusGone, "EDGE_USAGE_CURSOR_EXPIRED", "cursor expired, restart from the beginning")
	case err != nil:
		log.Printf("[USAGE] page: %v", err)
		writeProblem(w, http.StatusInternalServerError, "EDGE_INTERNAL", "internal error")
	default:
		if recs == nil {
			recs = []UsageRecord{}
		}
		writeAPIJSON(w, usagePage{NodeID: a.nodeID, Records: recs, NextCursor: next})
	}
	return true
}

// take 按固定一分钟窗口计数；超限时返回距窗口结束的秒数（≥1）。
func (a *usageAPI) take() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if now.Sub(a.windowStart) >= time.Minute {
		a.windowStart, a.count = now, 0
	}
	if a.count >= usageAPIRatePerMinute {
		return int(a.windowStart.Add(time.Minute).Sub(now)/time.Second) + 1
	}
	a.count++
	return 0
}

func writeAPIJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeProblem 写 RFC 9457 problem details；code 取自 api/errors.yaml。
func writeProblem(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"type": "about:blank", "title": title, "code": code})
}
