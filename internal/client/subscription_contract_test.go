// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"os"
	"path/filepath"
	"testing"
)

// C5：客户端解析契约示例（api/testdata/subscription-*.json）。旧格式（别名字段、已废弃且对不上的签名）仍须正常解析。
func TestSubscriptionContractExamples(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "api", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	v3, err := ParseSubscriptionBytes(read("subscription-v3.json"))
	if err != nil {
		t.Fatalf("v3: %v", err)
	}
	s := v3.Servers[0]
	if v3.UserID != "alice" || v3.ExpireAt != 1893456000 || v3.TrafficLimitBytes != 107374182400 || s.Address != "us.example.net:443" ||
		s.SNI != "us.example.net" || s.ECH != "AEX0001" || len(s.AltPorts) != 3 || s.PurityScore != 95 || s.Country != "US" {
		t.Fatalf("v3 parsed: %+v %+v", v3, s)
	}

	legacy, err := ParseSubscriptionBytes(read("subscription-legacy.json"))
	if err != nil {
		t.Fatalf("legacy document (deprecated signature, alias fields) rejected: %v", err)
	}
	l := legacy.Servers[0]
	if legacy.ExpireAt != 1893456000 || legacy.TrafficLimitBytes != 107374182400 || l.SNI != "us.example.net" || l.ECH != "AEX0001" ||
		len(l.AltPorts) != 1 || l.ISPAffinity != "BGP" || l.PurityScore != 95 || !l.WarpActive || l.Country != "US" {
		t.Fatalf("legacy aliases not mapped: %+v %+v", legacy, l)
	}
	if _, err := ApplySubscription(v3); err != nil {
		t.Fatalf("apply v3: %v", err)
	}
}
