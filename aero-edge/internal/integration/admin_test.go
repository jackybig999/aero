package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
	"github.com/aero-protocol/aero-edge/internal/connlimit"
	"github.com/aero-protocol/aero-edge/internal/metrics"
	"github.com/aero-protocol/aero-edge/internal/tokenstore"
)

// 通过 cmd 包会循环依赖，这里用最小 handler 行为测 tokenstore + 鉴权逻辑。
// 完整 HTTP Admin 在 main 包；本测验证持久化与重载契约。

func TestTokenStoreAdminLifecycle(t *testing.T) {
	dir := t.TempDir()
	v := auth.NewValidator()
	s, err := tokenstore.Open(dir, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ensure("boot", "default", time.Hour); err != nil {
		t.Fatal(err)
	}
	tok, err := s.AddReturn("", "u2", time.Hour)
	if err != nil || tok == "" {
		t.Fatalf("add: %v %q", err, tok)
	}
	if !v.Validate(tok) {
		t.Fatal("new token invalid")
	}
	if err := s.Remove(tok); err != nil {
		t.Fatal(err)
	}
	if v.Validate(tok) {
		t.Fatal("removed still valid")
	}
	// 重写文件后 Reload
	if err := s.Ensure("boot", "default", time.Hour); err != nil {
		t.Fatal(err)
	}
	v2 := auth.NewValidator()
	s2, err := tokenstore.Open(dir, v2)
	if err != nil {
		t.Fatal(err)
	}
	if !v2.Validate("boot") {
		t.Fatal("reload boot")
	}
	n, err := s2.Reload()
	if err != nil || n < 1 {
		t.Fatalf("reload n=%d err=%v", n, err)
	}
	_ = filepath.Join(dir, "tokens.json")
}

func TestConnLimitRejects(t *testing.T) {
	l := connlimit.New(1, 1)
	if !l.TryAcquire("a") {
		t.Fatal("first")
	}
	if l.TryAcquire("a") {
		t.Fatal("should reject")
	}
	l.Release("a")
	if !l.TryAcquire("a") {
		t.Fatal("after release")
	}
}

func TestMetricsRejectCounters(t *testing.T) {
	r := metrics.NewRegistry()
	r.CapacityReject()
	r.RateReject()
	r.IdleTimeout()
	snap := r.Snapshot()
	if snap.CapacityRejects != 1 || snap.RateRejects != 1 || snap.IdleTimeouts != 1 {
		t.Fatalf("%+v", snap)
	}
	// JSON shape stable
	b, _ := json.Marshal(snap)
	if !bytes.Contains(b, []byte("capacity_rejects")) {
		t.Fatalf("json: %s", b)
	}
	_ = httptest.NewRequest(http.MethodGet, "/", nil)
}
