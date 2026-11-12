package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const testMeteringKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestUsageAPI(t *testing.T) (*usageAPI, *UsageMeter, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
	m, _ := newTestMeter(t, &now)
	a := newUsageAPI(m, testMeteringKey, "node-test", func() nodeStatus {
		return nodeStatus{Version: "test", Ready: true, ActiveSessions: 2, SessionsByUID: []uidSession{{UID: "user_alice01", Sessions: 2}}}
	})
	a.now = func() time.Time { return now }
	return a, m, &now
}

func usageReq(a *usageAPI, method, target, key string) (bool, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, target, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	return a.TryServe(rec, req), rec
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("not a problem response: %s %q", rec.Header().Get("Content-Type"), rec.Body.String())
	}
	return p["code"]
}

// 未鉴权、密钥错误、非 GET、管理密钥：一律不处理（落到伪装站），不暴露接口存在。
func TestUsageAPIUnauthenticatedFallsThroughToCover(t *testing.T) {
	a, _, _ := newTestUsageAPI(t)
	for name, tc := range map[string][3]string{
		"no key":    {http.MethodGet, "/v1/usage", ""},
		"wrong key": {http.MethodGet, "/v1/status", strings.Repeat("f", 64)},
		"prefix":    {http.MethodGet, "/v1/usage", testMeteringKey[:32]},
		"post":      {http.MethodPost, "/v1/usage", testMeteringKey},
		"other":     {http.MethodGet, "/v1/admin", testMeteringKey},
	} {
		if handled, rec := usageReq(a, tc[0], tc[1], tc[2]); handled || rec.Body.Len() != 0 {
			t.Errorf("%s: handled=%v body=%q", name, handled, rec.Body.String())
		}
	}
	var nilAPI *usageAPI // usage_api 关闭
	if handled, _ := usageReq(nilAPI, http.MethodGet, "/v1/usage", testMeteringKey); handled {
		t.Fatal("disabled API handled a request")
	}
}

func TestUsageAPIPagesAndStatus(t *testing.T) {
	a, m, _ := newTestUsageAPI(t)
	handled, rec := usageReq(a, http.MethodGet, "/v1/usage", testMeteringKey)
	if !handled || rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"records":[]`) {
		t.Fatalf("empty page: %d %s", rec.Code, rec.Body.String())
	}
	m.Cell(usageToken("user_alice01")).Add(10, 20)
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	_, rec = usageReq(a, http.MethodGet, "/v1/usage?limit=1", testMeteringKey)
	var page usagePage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || page.NodeID != "node-test" || len(page.Records) != 1 ||
		page.Records[0].BytesDown != 20 || page.NextCursor != "1" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("page: %+v %v", page, err)
	}
	for _, cur := range []string{"abc", "-1", strings.Repeat("9", 65)} {
		if _, rec := usageReq(a, http.MethodGet, "/v1/usage?cursor="+cur, testMeteringKey); rec.Code != http.StatusGone || problemCode(t, rec) != "EDGE_USAGE_CURSOR_EXPIRED" {
			t.Fatalf("cursor %q: %d %s", cur, rec.Code, rec.Body.String())
		}
	}
	_, rec = usageReq(a, http.MethodGet, "/v1/status", testMeteringKey)
	var st nodeStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.NodeID != "node-test" || st.ActiveSessions != 2 || len(st.SessionsByUID) != 1 {
		t.Fatalf("status: %+v %v", st, err)
	}
}

// 每个密钥 60 次/分钟：超限 429 + Retry-After，窗口过后恢复。
func TestUsageAPIRateLimit(t *testing.T) {
	a, _, now := newTestUsageAPI(t)
	for i := 0; i < usageAPIRatePerMinute; i++ {
		if _, rec := usageReq(a, http.MethodGet, "/v1/status", testMeteringKey); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	_, rec := usageReq(a, http.MethodGet, "/v1/usage", testMeteringKey)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || problemCode(t, rec) != "EDGE_RATE_LIMITED" {
		t.Fatalf("over limit: %d %v", rec.Code, rec.Header())
	}
	*now = now.Add(time.Minute)
	if _, rec := usageReq(a, http.MethodGet, "/v1/status", testMeteringKey); rec.Code != http.StatusOK {
		t.Fatalf("after window: %d", rec.Code)
	}
}

// 契约守卫：响应结构包含 api/edge-public.yaml 的全部 required 字段；接口使用的错误码已在 api/errors.yaml 登记。
func TestUsageAPIMatchesContract(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "edge-public.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Required   []string       `yaml:"required"`
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for schema, v := range map[string]any{"UsagePage": usagePage{}, "UsageRecord": UsageRecord{}, "NodeStatus": nodeStatus{}} {
		fields := map[string]bool{}
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			fields[strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]] = true
		}
		s, ok := doc.Components.Schemas[schema]
		if !ok {
			t.Fatalf("schema %s missing from contract", schema)
		}
		for _, f := range s.Required {
			if !fields[f] {
				t.Errorf("%s: required field %q not produced", schema, f)
			}
		}
		for f := range fields {
			if _, ok := s.Properties[f]; !ok {
				t.Errorf("%s: field %q not in contract", schema, f)
			}
		}
	}
	reg, err := os.ReadFile(filepath.Join("..", "..", "api", "errors.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("usage_api.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`"(EDGE_[A-Z_]+)"`).FindAllStringSubmatch(string(src), -1) {
		if !strings.Contains(string(reg), "\n"+m[1]+":") {
			t.Errorf("error code %s not registered in api/errors.yaml", m[1])
		}
	}
}

// Server 集成：开启后生成并持久化密钥与节点标识（重启不变）；经 ServeHTTP 未鉴权看到伪装站。
func TestServerUsageAPILifecycle(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "edge.json")
	start := func(enabled bool) (*Server, map[string]any) {
		t.Helper()
		var cfg ServerConfig // 与 cmd/edge 相同：先读已持久化的配置文件
		if b, err := os.ReadFile(cfgPath); err == nil {
			if err := json.Unmarshal(b, &cfg); err != nil {
				t.Fatal(err)
			}
		}
		listen, host := findTestAddr()
		cfg.Listen, cfg.Domain, cfg.DataDir, cfg.ConfigPath = listen, host, filepath.Join(dir, "data"), cfgPath
		cfg.UsageAPI, cfg.AllowSelfSignedCertForTest = enabled, true
		srv, err := NewServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(cfgPath)
		var persisted map[string]any
		_ = json.Unmarshal(b, &persisted)
		return srv, persisted
	}
	get := func(srv *Server, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	srv, p1 := start(true)
	if err := srv.Start(); err != nil { // 启动落盘协程；Close 须等它退出后再关闭数据库
		t.Fatal(err)
	}
	key, _ := p1["metering_key"].(string)
	node, _ := p1["node_id"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(key) || !strings.HasPrefix(node, "node-") {
		t.Fatalf("persisted identity: key len %d node %q", len(key), node)
	}
	if rec := get(srv, ""); !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("unauthenticated request did not get the cover page: %s", rec.Header().Get("Content-Type"))
	}
	if rec := get(srv, key); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"node_id":"`+node+`"`) {
		t.Fatalf("authenticated status: %d %s", rec.Code, rec.Body.String())
	}
	srv.Close()

	srv, p2 := start(true)
	if p2["metering_key"] != key || p2["node_id"] != node {
		t.Fatal("metering identity changed across restart")
	}
	srv.Close()

	srv, _ = start(false) // usage_api 关闭：即使持有密钥也只看到伪装站
	defer srv.Close()
	if rec := get(srv, key); !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatal("usage API reachable while usage_api is off")
	}
}
