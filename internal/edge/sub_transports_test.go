// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func serverTransports(t *testing.T, body []byte) [][]string {
	t.Helper()
	var d SubDocument
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, s := range d.Servers {
		out = append(out, s.Transports)
	}
	return out
}

// 所有订阅输出（默认、管理员、用户、client-sub.json）的每个节点都声明 transports（C5 §3）；
// 它由程序决定，不写入 sub_meta.json，所以旧版本留下的元数据升级后也会带上。
func TestSubscriptionOutputsDeclareTransports(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSubStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ensure(EnsureSubParams{Name: "n1", Host: "n1.example.com", SNI: "n1.example.com", Token: "tok_main", Address: "n1.example.com:443"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertUserSub(UserSub{Username: "bob", Slug: "bob1234567", Token: "tok_bob", ExpireAt: 1893456000}); err != nil {
		t.Fatal(err)
	}
	want := []string{"datagram", "capsule"}

	def, err := store.DocumentJSON()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.AdminDocumentJSON()
	if err != nil {
		t.Fatal(err)
	}
	us, _ := store.GetUserSub("bob1234567")
	user, err := store.UserDocumentJSON(us)
	if err != nil {
		t.Fatal(err)
	}
	clientSub, err := os.ReadFile(filepath.Join(dir, "client-sub.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"default": def, "admin": admin, "user": user, "client-sub.json": clientSub} {
		assertSubConforms(t, body) // 字段必须在 api/subscription.schema.json 里
		got := serverTransports(t, body)
		if len(got) == 0 {
			t.Fatalf("%s: no servers", name)
		}
		for i, tr := range got {
			if !reflect.DeepEqual(tr, want) {
				t.Errorf("%s: server %d transports = %v, want %v", name, i, tr, want)
			}
		}
	}

	// 不持久化：元数据文件里没有 transports，内存里的文档也没被改写。
	meta, err := os.ReadFile(filepath.Join(dir, "sub_meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Document struct {
			Servers []map[string]any `json:"servers"`
		} `json:"document"`
	}
	if err := json.Unmarshal(meta, &raw); err != nil {
		t.Fatal(err)
	}
	for _, s := range raw.Document.Servers {
		if _, ok := s["transports"]; ok {
			t.Fatalf("transports persisted in sub_meta.json: %v", s)
		}
	}
	if d := store.Document(); d.Servers[0].Transports != nil {
		t.Fatalf("in-memory document was modified: %v", d.Servers[0].Transports)
	}

	// 旧元数据（没有 transports）重新载入后，输出仍然带上。
	store2, err := NewSubStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	def2, err := store2.DocumentJSON()
	if err != nil {
		t.Fatal(err)
	}
	if got := serverTransports(t, def2); len(got) == 0 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("after reload: %v", got)
	}
}
