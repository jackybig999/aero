// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package sub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestSubscriptionMultiVPSFailoverFetch(t *testing.T) {
	now := time.Now().Unix()

	// 1. 模拟备用节点服务器 (TS2: 正常运行)
	backupDoc := &Subscription{
		Version:   "aero/2.0",
		UserID:    "jacky",
		ExpireAt:  now + 86400*30,
		CreatedAt: now,
		Servers: []ServerConfig{
			{
				Name:     "JP-Edge-02",
				Address:  "127.0.0.1:8443",
				Token:    "token-jacky-999",
				SNI:      "jp02.aero.net",
				Protocol: "quic",
			},
		},
	}
	rawBackup, _ := json.Marshal(backupDoc)

	tsBackup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sub/jacky888abc" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(rawBackup)
			return
		}
		http.NotFound(w, r)
	}))
	defer tsBackup.Close()

	uBackup, _ := url.Parse(tsBackup.URL)

	// 2. 模拟故障的主节点服务器 (TS1: 始终返回 503 宕机)
	tsPrimary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "VPS-A Down", http.StatusServiceUnavailable)
	}))
	defer tsPrimary.Close()

	// 3. 在客户端预置历史缓存 (包含备用节点 TS2 的真实监听地址)
	cachedDoc := &Subscription{
		Version:  "aero/2.0",
		UserID:   "jacky",
		ExpireAt: now + 86400*30,
		Servers: []ServerConfig{
			{
				Name:    "HK-Edge-01",
				Address: "127.0.0.1:443", // 模拟挂掉的节点
			},
			{
				Name:    "JP-Edge-02",
				Address: uBackup.Host, // 备用节点的真实地址
			},
		},
	}
	cachedJSON, _ := json.Marshal(cachedDoc)
	SaveLastBody(cachedJSON)

	// 4. 发起拉取主节点 TS1 的订阅: /sub/jacky888abc
	// 期望：TS1 挂掉后，Fetch 自动感知并利用缓存中的服务器地址，向 TS2 拉取相同 slug
	primaryURL := tsPrimary.URL + "/sub/jacky888abc"
	fetchedSub, err := Fetch(primaryURL, FetchOptions{
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("expected failover to backup server to succeed, got error: %v", err)
	}

	if len(fetchedSub.Servers) != 1 || fetchedSub.Servers[0].Name != "JP-Edge-02" {
		t.Fatalf("expected subscription from backup server JP-Edge-02, got: %+v", fetchedSub.Servers)
	}

	t.Logf("[SUCCESS] Multi-VPS Failover Fetch verified! Seamlessly hopped from down VPS-A to alive VPS-B.")
}
