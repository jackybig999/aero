package mobile_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aero-protocol/aero-ech/mobile"
)

func TestMobileAPI_Lifecycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"version": "aero/2.0",
			"servers": [
				{"name": "JP-Edge-1", "address": "jp1.aero.net:443", "token": "tok1"},
				{"name": "US-Edge-2", "address": "us2.aero.net:443", "token": "tok2"}
			]
		}`))
	}))
	defer server.Close()

	// 1. 启动引擎
	err := mobile.Start(server.URL, "tun", "mobile_test_tok")
	if err != nil {
		t.Fatalf("mobile.Start failed: %v", err)
	}

	// 2. 状态查询
	statusJSON := mobile.GetStatus()
	var st map[string]any
	if err := json.Unmarshal([]byte(statusJSON), &st); err != nil {
		t.Fatalf("invalid json status: %v", err)
	}
	if st["connected"] != true || st["active_node"] != "JP-Edge-1" {
		t.Fatalf("unexpected mobile status: %+v", st)
	}

	// 3. 节点切换
	if err := mobile.SwitchNode("US-Edge-2"); err != nil {
		t.Fatalf("SwitchNode failed: %v", err)
	}
	st2JSON := mobile.GetStatus()
	_ = json.Unmarshal([]byte(st2JSON), &st)
	if st["active_node"] != "US-Edge-2" {
		t.Fatalf("expected active_node US-Edge-2, got %v", st["active_node"])
	}

	// 4. 热更新配置
	if err := mobile.SetConfig(`{"dns_ttl": 60}`); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	// 5. 停止引擎
	if err := mobile.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	st3JSON := mobile.GetStatus()
	_ = json.Unmarshal([]byte(st3JSON), &st)
	if st["connected"] != false {
		t.Fatalf("expected connected=false after stop")
	}
}
