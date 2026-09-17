// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package sub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSubscriptionLifecycleAndVerification(t *testing.T) {
	key := []byte("secret-edge-token-2026")
	now := time.Now().Unix()

	// 1. 构造标准订阅文档
	subObj := &Subscription{
		Version:   "1.0",
		UserID:    "user-test-8888",
		ExpireAt:  now + 86400*30,
		CreatedAt: now,
		Servers: []ServerConfig{
			{
				Name:     "Tokyo-Edge-01",
				Address:  "104.28.1.1:443",
				Token:    string(key),
				SNI:      "edge.aero.net",
				Protocol: "aero_h2",
				PinSPKI:  []string{"spki_sha256_mock_hash_base64"},
			},
		},
		Opt: Optimization{
			DefaultQoS: "ultra-low-latency",
			Bandwidth:  "1000Mbps",
		},
	}

	// 2. 使用 Token 进行 HMAC 签名
	sig := Sign(subObj, key)
	if sig == "" {
		t.Fatalf("expected non-empty signature")
	}
	subObj.Signature = sig

	// 3. 校验签名
	if !Verify(subObj, key) {
		t.Fatalf("expected signature verification to pass")
	}

	// 4. 模拟篡改数据校验失败
	subObjTampered := *subObj
	subObjTampered.Servers = append([]ServerConfig{}, subObj.Servers...)
	subObjTampered.Servers[0].Address = "104.28.1.99:443" // 恶意篡改 IP
	if Verify(&subObjTampered, key) {
		t.Fatalf("expected tampered subscription verification to fail")
	}

	// 5. 模拟订阅服务器提供 HTTP 服务
	rawJSON, err := json.Marshal(subObj)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rawJSON)
	}))
	defer ts.Close()

	// 6. 客户端执行 Fetch
	fetchedSub, err := Fetch(ts.URL, FetchOptions{
		Timeout:      5 * time.Second,
		DisableCache: true,
	})
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if len(fetchedSub.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(fetchedSub.Servers))
	}
	srv := fetchedSub.Servers[0]
	if srv.Name != "Tokyo-Edge-01" || srv.Address != "104.28.1.1:443" {
		t.Errorf("server details mismatch: %+v", srv)
	}

	if !Verify(fetchedSub, key) {
		t.Errorf("fetched subscription signature verification failed")
	}

	t.Logf("[SUCCESS] Sub integration test passed! Node: %s (%s), Protocol: %s",
		srv.Name, srv.Address, srv.Protocol)
}
