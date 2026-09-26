// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package subscribe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestDualTrackSubscription(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sub_dual_track_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewStore(tempDir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	// 1. 初始化老单节点订阅
	err = store.Ensure(EnsureParams{
		Name:    "default-node",
		Address: "1.2.3.4:443",
		Token:   "legacy-master-token-32hex",
		SNI:     "myconsun.cc.cd",
	})
	if err != nil {
		t.Fatalf("ensure store: %v", err)
	}
	legacySecret := store.Secret()
	if legacySecret == "" {
		t.Fatalf("expected non-empty legacy secret")
	}

	handler := &Handler{Store: store}

	// 2. 测试老版 32-Hex 订阅链接: GET /sub/{legacySecret}
	reqLegacy := httptest.NewRequest(http.MethodGet, "/sub/"+legacySecret, nil)
	recLegacy := httptest.NewRecorder()
	handled := handler.TryServe(recLegacy, reqLegacy)
	if !handled {
		t.Fatalf("expected handler to serve /sub/%s", legacySecret)
	}
	if recLegacy.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for legacy secret, got %d", recLegacy.Code)
	}
	var legacyDoc Document
	if err := json.Unmarshal(recLegacy.Body.Bytes(), &legacyDoc); err != nil {
		t.Fatalf("unmarshal legacy doc: %v", err)
	}
	if len(legacyDoc.Servers) != 1 || legacyDoc.Servers[0].Name != "default-node" {
		t.Fatalf("unexpected legacy doc servers: %+v", legacyDoc.Servers)
	}

	// 3. 添加用户专属 Slug 订阅 (多节点聚合)
	now := time.Now().Unix()
	userSlug := "jacky888abc"
	userToken := "usr_token_jacky_999"
	err = store.UpsertUserSub(UserSub{
		Username: "jacky",
		Slug:     userSlug,
		Token:    userToken,
		ExpireAt: now + 86400*30, // 30天后到期
		Servers: []Server{
			{
				Name:     "HK-Node-01",
				Address:  "103.1.1.1:443",
				Token:    userToken,
				SNI:      "hk01.aero.net",
				Protocol: "quic",
			},
			{
				Name:     "JP-Node-02",
				Address:  "104.2.2.2:8443",
				Token:    userToken,
				SNI:      "jp02.aero.net",
				Protocol: "quic",
			},
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("upsert user sub: %v", err)
	}

	// 4. 测试用户专属 Slug 订阅: GET /sub/jacky888abc
	reqUser := httptest.NewRequest(http.MethodGet, "/sub/"+userSlug, nil)
	recUser := httptest.NewRecorder()
	handled = handler.TryServe(recUser, reqUser)
	if !handled {
		t.Fatalf("expected handler to serve /sub/%s", userSlug)
	}
	if recUser.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for user slug, got %d", recUser.Code)
	}
	var userDoc Document
	if err := json.Unmarshal(recUser.Body.Bytes(), &userDoc); err != nil {
		t.Fatalf("unmarshal user doc: %v", err)
	}
	if userDoc.UserID != "jacky" {
		t.Errorf("expected userID jacky, got %s", userDoc.UserID)
	}
	if len(userDoc.Servers) != 2 {
		t.Fatalf("expected 2 servers in multi-vps document, got %d", len(userDoc.Servers))
	}
	if userDoc.Servers[0].Name != "HK-Node-01" || userDoc.Servers[1].Name != "JP-Node-02" {
		t.Errorf("servers mismatch: %+v", userDoc.Servers)
	}

	// 5. 测试过期用户专属 Slug 订阅
	expiredSlug := "alexexpired123"
	err = store.UpsertUserSub(UserSub{
		Username:  "alex",
		Slug:      expiredSlug,
		Token:     "expired_token",
		ExpireAt:  now - 3600, // 已过期1小时
		CreatedAt: now - 7200,
	})
	if err != nil {
		t.Fatalf("upsert expired sub: %v", err)
	}
	reqExpired := httptest.NewRequest(http.MethodGet, "/sub/"+expiredSlug, nil)
	recExpired := httptest.NewRecorder()
	handled = handler.TryServe(recExpired, reqExpired)
	if !handled {
		t.Fatalf("expected handler to serve /sub/%s", expiredSlug)
	}
	if recExpired.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for expired sub, got %d", recExpired.Code)
	}

	// 6. 测试不存在的非法探测 Slug
	reqFake := httptest.NewRequest(http.MethodGet, "/sub/hacker666abc", nil)
	recFake := httptest.NewRecorder()
	handled = handler.TryServe(recFake, reqFake)
	if !handled {
		t.Fatalf("expected handler to handle fake slug")
	}
	if recFake.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for fake slug, got %d", recFake.Code)
	}

	// 7. 测试删除后再次访问
	err = store.DeleteUserSub(userSlug)
	if err != nil {
		t.Fatalf("delete user sub: %v", err)
	}
	recUserDeleted := httptest.NewRecorder()
	handler.TryServe(recUserDeleted, reqUser)
	if recUserDeleted.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after deletion, got %d", recUserDeleted.Code)
	}

	// 8. 确认老版单节点订阅依然正常
	recLegacyAgain := httptest.NewRecorder()
	handler.TryServe(recLegacyAgain, reqLegacy)
	if recLegacyAgain.Code != http.StatusOK {
		t.Fatalf("expected legacy sub to still work after user ops, got %d", recLegacyAgain.Code)
	}
}
