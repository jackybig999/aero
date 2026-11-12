package edge

import (
	"bytes"
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

const testAdminKey = "remote-admin-key-0123456789abcdef"

type remoteFixture struct {
	srv     *Server
	cfgPath string
	certDir string
}

// newRemoteFixture 启动一个使用文件证书的 edge（可测试证书重新加载）。
func newRemoteFixture(t *testing.T, enabled *bool) *remoteFixture {
	t.Helper()
	dir := t.TempDir()
	certDir := filepath.Join(dir, "cert")
	cf, kf := writeTestCert(t, certDir, "fullchain.pem", "privkey.pem", time.Now().Add(30*24*time.Hour), "node.example.com")
	listen, host := findTestAddr()
	cfgPath := filepath.Join(dir, "edge.json")
	srv, err := NewServer(ServerConfig{Listen: listen, Domain: host, DataDir: filepath.Join(dir, "data"), ConfigPath: cfgPath,
		AdminKey: testAdminKey, CertFile: cf, KeyFile: kf, RemoteAdminV1: enabled, AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return &remoteFixture{srv: srv, cfgPath: cfgPath, certDir: certDir}
}

func (f *remoteFixture) do(method, target, key string, body any) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if s, ok := body.(string); ok {
		rd = bytes.NewReader([]byte(s))
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rd)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	return rec
}

func isCover(rec *httptest.ResponseRecorder) bool {
	return strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html")
}

func (f *remoteFixture) persisted(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// 关闭、未鉴权、密钥错误、URL 中的密钥、未知路径：一律伪装站；旧 /admin/* 未鉴权也不再返回 403。
func TestRemoteAdminHiddenUnlessAuthenticated(t *testing.T) {
	off := newRemoteFixture(t, new(bool)) // 显式 false
	def := newRemoteFixture(t, nil)       // 未配置：默认开启
	if rec := def.do(http.MethodGet, "/admin/v1/status", testAdminKey, nil); rec.Code != http.StatusOK || isCover(rec) {
		t.Fatalf("default (unset) must enable C13: %d", rec.Code)
	}
	if rec := off.do(http.MethodGet, "/admin/v1/status", testAdminKey, nil); !isCover(rec) {
		t.Fatalf("flag off: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	f := newRemoteFixture(t, nil)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"no key":       f.do(http.MethodGet, "/admin/v1/status", "", nil),
		"wrong key":    f.do(http.MethodGet, "/admin/v1/status", "wrong", nil),
		"key in query": f.do(http.MethodGet, "/admin/v1/status?key="+testAdminKey, "", nil),
		"unknown path": f.do(http.MethodGet, "/admin/v1/exec", testAdminKey, nil),
		"wrong method": f.do(http.MethodDelete, "/admin/v1/status", testAdminKey, nil),
		"legacy":       f.do(http.MethodGet, "/admin/subs", "wrong", nil),
	} {
		if !isCover(rec) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	if rec := f.do(http.MethodGet, "/admin/subs", testAdminKey, nil); rec.Code != http.StatusOK || isCover(rec) {
		t.Fatalf("legacy subs with key: %d", rec.Code)
	}
	if rec := f.do(http.MethodGet, "/admin/status", testAdminKey, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("removed legacy /admin/status still served: %d", rec.Code)
	}
}

func TestRemoteAdminStatusAndCertReload(t *testing.T) {
	f := newRemoteFixture(t, nil)
	rec := f.do(http.MethodGet, "/admin/v1/status", testAdminKey, nil)
	var st remoteStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status: %d %v %s", rec.Code, err, rec.Body.String())
	}
	if !st.Ready || st.Version != Version || len(st.ListenPorts) == 0 || st.Cert.DaysLeft < 28 || st.UsageAPI || st.Host.DiskTotal == 0 {
		t.Fatalf("status: %+v", st)
	}
	if strings.Contains(rec.Body.String(), testAdminKey) {
		t.Fatal("status leaks the admin key")
	}
	// 续期：证书文件被替换（到期更晚）后重新加载
	writeTestCert(t, f.certDir, "fullchain.pem", "privkey.pem", time.Now().Add(89*24*time.Hour), "node.example.com")
	rec = f.do(http.MethodPost, "/admin/v1/cert/reload", testAdminKey, nil)
	var ci certInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &ci); err != nil || ci.DaysLeft < 87 {
		t.Fatalf("after reload: %d %+v %v", rec.Code, ci, err)
	}
}

// 计量开关：开启返回密钥并持久化，C6 接口随之可用；关闭后 C6 回到伪装站并持久化。
func TestRemoteAdminUsageToggle(t *testing.T) {
	f := newRemoteFixture(t, nil)
	if rec := f.do(http.MethodPut, "/admin/v1/usage-api", testAdminKey, `{"enabled":true,"x":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", rec.Code)
	}
	if rec := f.do(http.MethodPut, "/admin/v1/usage-api", testAdminKey, `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing enabled accepted: %d", rec.Code)
	}
	rec := f.do(http.MethodPut, "/admin/v1/usage-api", testAdminKey, map[string]bool{"enabled": true})
	var us usageAPIState
	if err := json.Unmarshal(rec.Body.Bytes(), &us); err != nil || !us.Enabled || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(us.MeteringKey) || us.NodeID == "" {
		t.Fatalf("enable: %d %+v %v", rec.Code, us, err)
	}
	if p := f.persisted(t); p["usage_api"] != true || p["metering_key"] != us.MeteringKey {
		t.Fatalf("not persisted: %v", p["usage_api"])
	}
	if rec := f.do(http.MethodGet, "/v1/status", us.MeteringKey, nil); rec.Code != http.StatusOK || isCover(rec) {
		t.Fatalf("C6 not served after enable: %d", rec.Code)
	}
	again := f.do(http.MethodGet, "/admin/v1/usage-api", testAdminKey, nil)
	if !strings.Contains(again.Body.String(), us.MeteringKey) {
		t.Fatal("GET usage-api does not return the key")
	}

	rec = f.do(http.MethodPut, "/admin/v1/usage-api", testAdminKey, map[string]bool{"enabled": false})
	var off usageAPIState
	if err := json.Unmarshal(rec.Body.Bytes(), &off); err != nil || off.Enabled || off.MeteringKey != "" || strings.Contains(rec.Body.String(), "metering_key") {
		t.Fatalf("disable: %s", rec.Body.String())
	}
	if rec := f.do(http.MethodGet, "/v1/status", f.srv.cfg.MeteringKey, nil); !isCover(rec) {
		t.Fatal("C6 still served after disable")
	}
	if p := f.persisted(t); p["usage_api"] != false {
		t.Fatalf("disable not persisted: %v", p["usage_api"])
	}
}

func TestRemoteAdminWarpRestartAndRateLimit(t *testing.T) {
	f := newRemoteFixture(t, nil)
	if rec := f.do(http.MethodPut, "/admin/v1/warp", testAdminKey, map[string]bool{"enabled": true}); rec.Code != http.StatusConflict || problemCode(t, rec) != "EDGE_WARP_UNAVAILABLE" {
		t.Fatalf("warp without local proxy: %d", rec.Code)
	}
	if rec := f.do(http.MethodPut, "/admin/v1/warp", testAdminKey, map[string]bool{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("warp off: %d", rec.Code)
	}
	if rec := f.do(http.MethodPost, "/admin/v1/restart", testAdminKey, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("restart: %d", rec.Code)
	}
	select {
	case <-f.srv.restartCh:
	case <-time.After(time.Second):
		t.Fatal("restart not requested")
	}
	f.do(http.MethodPost, "/admin/v1/restart", testAdminKey, nil) // 重复请求不 panic

	now := time.Now()
	f.srv.remoteAdmin.now = func() time.Time { return now }
	f.srv.remoteAdmin.lim = minuteLimiter{max: remoteAdminRatePerMinute}
	for i := 0; i < remoteAdminRatePerMinute; i++ {
		f.do(http.MethodGet, "/admin/v1/usage-api", testAdminKey, nil)
	}
	if rec := f.do(http.MethodGet, "/admin/v1/usage-api", testAdminKey, nil); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit: %d", rec.Code)
	}
}

// 契约守卫：响应结构与 api/edge-remote.yaml 的 schema 一致；使用的错误码已登记。
func TestRemoteAdminMatchesContract(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "edge-remote.yaml"))
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
	for schema, v := range map[string]any{"RemoteStatus": remoteStatus{}, "CertInfo": certInfo{}, "UsageAPIState": usageAPIState{}, "WarpState": warpState{}, "Purity": purityState{}} {
		s, ok := doc.Components.Schemas[schema]
		if !ok {
			t.Fatalf("schema %s missing", schema)
		}
		fields := map[string]bool{}
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			name := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
			fields[name] = true
			if _, ok := s.Properties[name]; !ok {
				t.Errorf("%s.%s not in contract", schema, name)
			}
		}
		for _, r := range s.Required {
			if !fields[r] {
				t.Errorf("%s: required %q missing", schema, r)
			}
		}
	}
	reg, _ := os.ReadFile(filepath.Join("..", "..", "api", "errors.yaml"))
	src, _ := os.ReadFile("remote_admin.go")
	for _, m := range regexp.MustCompile(`"(EDGE_[A-Z_]+)"`).FindAllStringSubmatch(string(src), -1) {
		if !strings.Contains(string(reg), "\n"+m[1]+":") {
			t.Errorf("error code %s not registered", m[1])
		}
	}
}
