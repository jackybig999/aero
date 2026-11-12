package sub

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeUsageEdge 按 api/edge-public.yaml 的行为提供 /v1/usage：seq > cursor、每页至多 pageSize 条、
// 游标小于 prunedBelow 返回 410、密钥错误返回伪装站（200 text/html）。
type fakeUsageEdge struct {
	mu          sync.Mutex
	nodeID, key string
	recs        []map[string]any // 按 seq 递增
	pageSize    int
	prunedBelow int64
	requests    int
}

func (f *fakeUsageEdge) put(uid, iss string, period, up, down int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seq := int64(len(f.recs) + 1)
	for i, r := range f.recs { // 同一 (uid, period) 更新：删除旧行，以新 seq 追加
		if r["uid"] == uid && r["period_start"] == period {
			f.recs = append(f.recs[:i], f.recs[i+1:]...)
			break
		}
	}
	if n := len(f.recs); n > 0 && f.recs[n-1]["seq"].(int64) >= seq {
		seq = f.recs[n-1]["seq"].(int64) + 1
	}
	f.recs = append(f.recs, map[string]any{"seq": seq, "uid": uid, "iss": iss, "period_start": period, "bytes_up": up, "bytes_down": down, "final": false})
}

func (f *fakeUsageEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if r.URL.Path != "/v1/usage" || r.Header.Get("Authorization") != "Bearer "+f.key {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>cover</html>"))
		return
	}
	cur := r.URL.Query().Get("cursor")
	after, _ := strconv.ParseInt(cur, 10, 64)
	if after > 0 && after < f.prunedBelow {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusGone)
		return
	}
	out := []map[string]any{}
	next := cur
	if next == "" {
		next = "0"
	}
	for _, rec := range f.recs {
		if rec["seq"].(int64) > after && len(out) < f.pageSize {
			out = append(out, rec)
			next = strconv.FormatInt(rec["seq"].(int64), 10)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"node_id": f.nodeID, "records": out, "next_cursor": next})
}

func newUsageFixture(t *testing.T) (*UsageCollector, *EndpointStore, func(f *fakeUsageEdge, vpsID uint64)) {
	t.Helper()
	dir := t.TempDir()
	eps, err := NewEndpointStore(filepath.Join(dir, "eps.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := OpenUsageCollector(filepath.Join(dir, "usage.db"), eps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	add := func(f *fakeUsageEdge, vpsID uint64) {
		srv := httptest.NewTLSServer(f)
		t.Cleanup(srv.Close)
		c.client = srv.Client() // 信任测试证书；生产使用系统根证书严格校验
		host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
		p, _ := strconv.Atoi(port)
		if err := eps.Upsert(EndpointInfo{VPSID: vpsID, Host: host, Port: p, Installed: true, MeteringKey: f.key}); err != nil {
			t.Fatal(err)
		}
	}
	return c, eps, add
}

func usageOf(t *testing.T, c *UsageCollector, uid string) (int64, int64) {
	t.Helper()
	up, down, err := c.UsageSince(uid, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	return up, down
}

// 分页读完、累计值覆盖写入（不累加）、只保留 iss=sub。
func TestUsageCollectorPagesAndOverwrites(t *testing.T) {
	c, _, add := newUsageFixture(t)
	edge := &fakeUsageEdge{nodeID: "node-a", key: "k1", pageSize: 2}
	add(edge, 1)
	const h = 1_762_934_400
	edge.put("alice-1", "sub", h, 100, 1000)
	edge.put("alice-1", "sub", h+3600, 1, 10)
	edge.put("bob-2", "sub", h, 5, 50)
	edge.put("ops-1", "edge", h, 9, 9)
	c.PollOnce(context.Background())
	if up, down := usageOf(t, c, "alice-1"); up != 101 || down != 1010 {
		t.Fatalf("alice after first poll: %d/%d", up, down)
	}
	if up, _ := usageOf(t, c, "ops-1"); up != 0 {
		t.Fatal("iss=edge record stored")
	}
	edge.put("alice-1", "sub", h, 150, 1500) // 同一小时累计值增长
	c.PollOnce(context.Background())
	c.PollOnce(context.Background()) // 无新数据：幂等
	if up, down := usageOf(t, c, "alice-1"); up != 151 || down != 1510 {
		t.Fatalf("cumulative value must overwrite, not add: %d/%d", up, down)
	}
}

// 多节点汇总；游标过期（410）从头重读；密钥错误（伪装站）不写入、不推进游标；未登记密钥的节点不轮询。
func TestUsageCollectorAcrossNodesAndRecovery(t *testing.T) {
	c, eps, add := newUsageFixture(t)
	a := &fakeUsageEdge{nodeID: "node-a", key: "ka", pageSize: 10}
	b := &fakeUsageEdge{nodeID: "node-b", key: "kb", pageSize: 10}
	add(a, 1)
	add(b, 2)
	a.put("carol-3", "sub", 3600, 10, 20)
	b.put("carol-3", "sub", 3600, 1, 2)
	c.PollOnce(context.Background())
	if up, down := usageOf(t, c, "carol-3"); up != 11 || down != 22 {
		t.Fatalf("cross-node sum: %d/%d", up, down)
	}

	a.put("carol-3", "sub", 7200, 5, 5)
	a.mu.Lock()
	a.prunedBelow = 99 // 已存游标 1 早于保留期
	a.mu.Unlock()
	c.PollOnce(context.Background())
	if up, _ := usageOf(t, c, "carol-3"); up != 16 {
		t.Fatalf("after 410 re-read: up=%d, want 16", up)
	}

	ep, _ := eps.Get(2)
	ep.MeteringKey = "wrong"
	_ = eps.Upsert(ep)
	b.put("carol-3", "sub", 7200, 7, 7)
	_, before, _ := c.cursor(2)
	c.PollOnce(context.Background())
	if _, after, _ := c.cursor(2); after != before {
		t.Fatalf("cursor advanced on a cover-page response: %q → %q", before, after)
	}
	if up, _ := usageOf(t, c, "carol-3"); up != 16 {
		t.Fatal("cover page response was stored")
	}

	ep.MeteringKey = ""
	_ = eps.Upsert(ep)
	b.mu.Lock()
	n := b.requests
	b.mu.Unlock()
	c.PollOnce(context.Background())
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.requests != n {
		t.Fatal("node without a metering key was polled")
	}
}

func TestEndpointPublicHidesMeteringKey(t *testing.T) {
	b, err := json.Marshal(EndpointInfo{VPSID: 1, MeteringKey: "secret-metering-key"}.public())
	if err != nil || strings.Contains(string(b), "secret-metering-key") || strings.Contains(string(b), "metering_key") {
		t.Fatalf("metering key exposed: %s %v", b, err)
	}
}
