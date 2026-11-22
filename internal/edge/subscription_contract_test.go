// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// assertSubConforms 按 api/subscription.schema.json（C5）检查订阅文档：必填字段齐全、只含已定义字段、
// version 与 protocol 取值正确。
func assertSubConforms(t *testing.T, body []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "subscription.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		Defs       struct {
			Server struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"server"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("subscription is not JSON: %v", err)
	}
	check := func(where string, obj map[string]any, required []string, props map[string]json.RawMessage) {
		for _, r := range required {
			if _, ok := obj[r]; !ok {
				t.Errorf("%s: required field %q missing", where, r)
			}
		}
		var extra []string
		for k := range obj {
			if _, ok := props[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		if len(extra) > 0 {
			t.Errorf("%s: fields not in C5 contract: %v", where, extra)
		}
	}
	check("document", doc, schema.Required, schema.Properties)
	if doc["version"] != "aero/3.0" {
		t.Errorf("version = %v", doc["version"])
	}
	servers, _ := doc["servers"].([]any)
	if len(servers) == 0 {
		t.Error("servers empty")
	}
	for _, s := range servers {
		srv, _ := s.(map[string]any)
		check("server", srv, schema.Defs.Server.Required, schema.Defs.Server.Properties)
		if srv["protocol"] != "connect-ip" {
			t.Errorf("server protocol = %v", srv["protocol"])
		}
	}
}

// 管理员订阅与用户订阅都符合 C5（含不再输出 signature 与 ech_config）。
func TestSubscriptionDocumentsConformToC5(t *testing.T) {
	store, err := NewSubStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure(EnsureSubParams{Name: "n1", Host: "n1.example.com", SNI: "n1.example.com", Token: "tok_main", Address: "n1.example.com:443", ECHConfig: "AEXAMPLE"}); err != nil {
		t.Fatal(err)
	}
	admin, err := store.AdminDocumentJSON()
	if err != nil {
		t.Fatal(err)
	}
	assertSubConforms(t, admin)
	if err := store.UpsertUserSub(UserSub{Username: "alice", Slug: "alice123456", Token: "tok_alice", ExpireAt: 1893456000}); err != nil {
		t.Fatal(err)
	}
	us, _ := store.GetUserSub("alice123456")
	user, err := store.UserDocumentJSON(us)
	if err != nil {
		t.Fatal(err)
	}
	assertSubConforms(t, user)
	var d SubDocument
	_ = json.Unmarshal(user, &d)
	if d.Servers[0].Token != "tok_alice" || d.Servers[0].ECH != "AEXAMPLE" {
		t.Fatalf("user doc: %+v", d.Servers[0])
	}
}
