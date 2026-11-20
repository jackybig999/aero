package desk

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func geoBridge(h http.Handler) *ClientBridge {
	b := NewClientBridge("http://127.0.0.1:19877")
	b.SetHTTPClient(&http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result(), nil
	})})
	return b
}

// 状态里的直连规则字段要原样带到桌面前端，而不是写死数字。
func TestBridgeStatusCarriesGeoFields(t *testing.T) {
	b := geoBridge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connected":true,"geo_rule_count":122870,"geo_updated_at":1790000000,"geo_error":"unexpected HTTP status 502"}`))
	}))
	st, err := b.GetStatus(false)
	if err != nil {
		t.Fatal(err)
	}
	if st.GeoRuleCount != 122870 || st.GeoUpdatedAt != 1790000000 || st.GeoError != "unexpected HTTP status 502" {
		t.Fatalf("geo 字段不对: %+v", st)
	}
}

func TestBridgeSyncGeoData(t *testing.T) {
	var method, path string
	b := geoBridge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","updated":true,"count":119912,"total":122870}`))
	}))
	res, err := b.SyncGeoData()
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/api/v1/geodata/sync" {
		t.Errorf("请求 = %s %s, 期望 POST /api/v1/geodata/sync", method, path)
	}
	if res["status"] != "ok" || res["updated"] != true || res["count"].(float64) != 119912 {
		t.Errorf("应答不对: %v", res)
	}

	// 客户端报告失败：原样带回 error，供界面显示
	b = geoBridge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","error":"geodata sync failed: timeout"}`))
	}))
	res, err = b.SyncGeoData()
	if err != nil || res["status"] != "error" || res["error"] != "geodata sync failed: timeout" {
		t.Errorf("失败应答 = (%v,%v)", res, err)
	}

	// 非 JSON（例如被代理的错误页）：返回错误而不是 panic
	b = geoBridge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	if _, err := b.SyncGeoData(); err == nil {
		t.Error("非 JSON 应答应报错")
	}
}

// ---- 本地代理端口以客户端真实监听地址为准 ----

func TestBridgeListenAddrFollowsClientStatus(t *testing.T) {
	listen := "127.0.0.1:8731"
	b := geoBridge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connected":true,"listen":"` + listen + `","resident_listening":true,"degraded":true,"degraded_reason":"x"}`))
	}))
	// 还没轮询过：取一次状态得到真实地址
	if got := b.ListenAddr(); got != "127.0.0.1:8731" {
		t.Fatalf("ListenAddr = %s, 期望客户端上报的 127.0.0.1:8731", got)
	}
	st, err := b.GetStatus(false)
	if err != nil || !st.ResidentListening || !st.Degraded || st.DegradedReason != "x" {
		t.Fatalf("状态字段不对: %+v %v", st, err)
	}
	// 客户端换了端口（例如重启后）：下一次状态轮询后跟随
	listen = "127.0.0.1:9457"
	if _, err := b.GetStatus(false); err != nil {
		t.Fatal(err)
	}
	if got := b.ListenAddr(); got != "127.0.0.1:9457" {
		t.Errorf("端口变化后应跟随，got %s", got)
	}
}

// 客户端不可达：退回默认地址；错误分支只用缓存值，不会再发一次请求（避免多等一次超时）。
func TestBridgeListenAddrFallsBackWhenClientDown(t *testing.T) {
	calls := 0
	b := geoBridge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	if got := b.cachedListen(); got != DefaultMixedProxy || calls != 0 {
		t.Errorf("cachedListen = %s (请求 %d 次)，期望默认地址且不发请求", got, calls)
	}
	if got := b.ListenAddr(); got != DefaultMixedProxy {
		t.Errorf("客户端不可达时应退回默认地址，got %s", got)
	}
}

// AI 工具注入的代理环境变量、API 测试的代理都取实时地址，而不是构造时写死的 55555。
func TestExecutorAndTesterUseLiveProxyAddress(t *testing.T) {
	live := "127.0.0.1:8731"
	ex := NewExecutor(nil, "127.0.0.1:55555")
	if env := strings.Join(ex.BuildProxyEnv(), "\n"); !strings.Contains(env, "HTTP_PROXY=http://127.0.0.1:55555") {
		t.Fatalf("未设置提供函数时应使用构造时的地址:\n%s", env)
	}
	ex.SetProxyProvider(func() string { return live })
	env := strings.Join(ex.BuildProxyEnv(), "\n")
	for _, want := range []string{"HTTP_PROXY=http://127.0.0.1:8731", "https_proxy=http://127.0.0.1:8731", "ALL_PROXY=socks5://127.0.0.1:8731"} {
		if !strings.Contains(env, want) {
			t.Errorf("环境变量应含 %q:\n%s", want, env)
		}
	}
	if strings.Contains(env, "55555") {
		t.Errorf("不应再出现写死的 55555:\n%s", env)
	}
	live = "127.0.0.1:9457" // 客户端换端口后下一次启动工具即生效
	if env := strings.Join(ex.BuildProxyEnv(), "\n"); !strings.Contains(env, "HTTP_PROXY=http://127.0.0.1:9457") {
		t.Errorf("应跟随新端口:\n%s", env)
	}
	// 提供函数返回空：退回构造时的地址
	ex.SetProxyProvider(func() string { return "" })
	if env := strings.Join(ex.BuildProxyEnv(), "\n"); !strings.Contains(env, "127.0.0.1:55555") {
		t.Errorf("提供函数返回空时应退回固定地址:\n%s", env)
	}

	tester := NewTester(nil, "127.0.0.1:55555")
	if tester.currentProxy() != "127.0.0.1:55555" {
		t.Error("Tester 默认应使用构造地址")
	}
	tester.SetProxyProvider(func() string { return live })
	if tester.currentProxy() != "127.0.0.1:9457" {
		t.Errorf("Tester 应使用实时地址，got %s", tester.currentProxy())
	}
}
