// Copyright 2026 AERO Protocol Contributors
package edgedb

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEdgeDBLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "edge.db")

	ed, err := Open(dbPath, "test-master-secret-123456")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer ed.Close()

	// 1. Test Token operations (encrypted at rest)
	token1 := "aero_secret_token_abcdef123456"
	label1 := "user_vip_01"
	exp1 := time.Now().Add(24 * time.Hour).Truncate(time.Second)

	if err := ed.SaveToken(token1, label1, exp1); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	list, err := ed.ListTokens()
	if err != nil {
		t.Fatalf("ListTokens failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 token, got %d", len(list))
	}
	if list[0].Token != token1 || list[0].Label != label1 {
		t.Errorf("token mismatch: got token=%s label=%s", list[0].Token, list[0].Label)
	}

	// 2. Test SNI Route
	targetType, targetAddr, found := ed.MatchSNIRoute("edge.microsoft.com")
	if !found || targetType != "reverse_proxy" || targetAddr != "https://www.bing.com" {
		t.Errorf("MatchSNIRoute failed: type=%s addr=%s found=%v", targetType, targetAddr, found)
	}

	// Test default fallback
	targetType, targetAddr, found = ed.MatchSNIRoute("unknown.domain.org")
	if !found || targetType != "cover_site" {
		t.Errorf("MatchSNIRoute default fallback failed: type=%s addr=%s", targetType, targetAddr)
	}

	// 3. Test Cert Encryption
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIB...fake...cert\n-----END CERTIFICATE-----"
	keyPEM := "-----BEGIN EC PRIVATE KEY-----\nMHQC...fake...key\n-----END EC PRIVATE KEY-----"
	spkiPin := "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="
	expCert := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)

	if err := ed.SaveCert("myconsun.cc.cd", certPEM, keyPEM, spkiPin, expCert); err != nil {
		t.Fatalf("SaveCert failed: %v", err)
	}

	gotCert, gotKey, gotPin, err := ed.GetCert("myconsun.cc.cd")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if gotCert != certPEM || gotKey != keyPEM || gotPin != spkiPin {
		t.Errorf("cert decryption mismatch!")
	}

	// 4. Test Traffic recording
	ed.RecordTraffic(token1, 1024, 2048)

	// 5. Test Delete
	if err := ed.DeleteToken(token1); err != nil {
		t.Fatalf("DeleteToken failed: %v", err)
	}
	listAfter, _ := ed.ListTokens()
	if len(listAfter) != 0 {
		t.Errorf("expected 0 tokens after delete, got %d", len(listAfter))
	}
}
