package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aero-protocol/aero-ech"
)

func TestSplitEngine_MatchRoute(t *testing.T) {
	engine := client.NewSplitEngine()

	// AI 专线测试
	if act := engine.MatchRoute("api.openai.com"); act != client.RouteAI {
		t.Fatalf("expected RouteAI for api.openai.com, got %v", act)
	}
	if act := engine.MatchRoute("claude.ai:443"); act != client.RouteAI {
		t.Fatalf("expected RouteAI for claude.ai, got %v", act)
	}
	if act := engine.MatchRoute("cursor.sh"); act != client.RouteAI {
		t.Fatalf("expected RouteAI for cursor.sh, got %v", act)
	}

	// 直连白名单测试
	if act := engine.MatchRoute("www.baidu.com"); act != client.RouteDirect {
		t.Fatalf("expected RouteDirect for baidu.com, got %v", act)
	}
	if act := engine.MatchRoute("tsinghua.edu.cn"); act != client.RouteDirect {
		t.Fatalf("expected RouteDirect for .edu.cn, got %v", act)
	}
	if act := engine.MatchRoute("192.168.1.100:8080"); act != client.RouteDirect {
		t.Fatalf("expected RouteDirect for LAN IP, got %v", act)
	}

	// 常规海外代理测试
	if act := engine.MatchRoute("youtube.com"); act != client.RouteProxy {
		t.Fatalf("expected RouteProxy for youtube.com, got %v", act)
	}
}

func TestSubscription_ParseAndBase64(t *testing.T) {
	rawJSON := `{
		"version": "aero/2.0",
		"userId": "jacky",
		"slug": "jacky123456",
		"servers": [
			{
				"name": "US-Clean-1",
				"address": "us1.aero.net:443",
				"token": "tok_123",
				"purityScore": 95,
				"aiBlocked": false
			}
		]
	}`

	// 1. 直接 JSON 解析
	sub1, err := client.ParseSubscriptionBytes([]byte(rawJSON))
	if err != nil {
		t.Fatalf("parse raw json failed: %v", err)
	}
	if len(sub1.Servers) != 1 || sub1.Servers[0].PurityScore != 95 {
		t.Fatalf("unexpected server in sub1: %+v", sub1)
	}

	// 2. Base64 编码解析
	b64 := base64.StdEncoding.EncodeToString([]byte(rawJSON))
	sub2, err := client.ParseSubscriptionBytes([]byte(b64))
	if err != nil {
		t.Fatalf("parse base64 failed: %v", err)
	}
	if sub2.Servers[0].Name != "US-Clean-1" {
		t.Fatalf("unexpected server in sub2: %+v", sub2)
	}
}

func TestSubscription_503CircuitBreak(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		purpose := r.URL.Query().Get("purpose")
		if purpose == "ai" {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":  503,
				"error": "TIER1_AI_NODES_EXHAUSTED",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version":"aero/2.0","servers":[]}`))
	}))
	defer server.Close()

	// 带有 purpose=ai 请求，服务端返回 503 时必须捕获 ErrTier1AIExhausted
	_, err := client.FetchSubscription(context.Background(), server.URL, client.SubFetchOptions{
		Purpose: "ai",
	})
	if err != client.ErrTier1AIExhausted {
		t.Fatalf("expected ErrTier1AIExhausted on 503, got %v", err)
	}
}
