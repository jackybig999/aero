// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVPSProfileValidationAndSigning(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	keyID := "test-edge-root-2026"
	RegisterTrustedRootKey(keyID, pub)

	now := time.Now().Unix()
	node := VPSProfileNode{
		NodeID:          "hk-01",
		ActivePort:      2083,
		ActiveTransport: "quic",
		SNI:             "hk-01.aero-protocol.com",
		ExpiresAt:       now + 3600,
	}

	if err := SignVPSProfileNode(priv, &node, keyID); err != nil {
		t.Fatalf("sign node: %v", err)
	}

	prof := &VPSProfile{
		Version: 1,
		Nodes: map[string]VPSProfileNode{
			"hk-01": node,
		},
	}

	// 1. Valid node passes
	if err := prof.ValidateNode(node, now); err != nil {
		t.Fatalf("expected valid node, got: %v", err)
	}

	// 2. Expired node rejected
	expiredNode := node
	expiredNode.ExpiresAt = now - 10
	if err := prof.ValidateNode(expiredNode, now); err != ErrNodeExpired {
		t.Fatalf("expected ErrNodeExpired, got: %v", err)
	}

	// 3. Invalid port rejected
	badPortNode := node
	badPortNode.ActivePort = 0
	if err := prof.ValidateNode(badPortNode, now); err != ErrInvalidNodePort {
		t.Fatalf("expected ErrInvalidNodePort, got: %v", err)
	}

	// 4. Tampered signature rejected
	tamperedNode := node
	tamperedNode.ActivePort = 8443 // Port changed without resigning
	if err := prof.ValidateNode(tamperedNode, now); err != ErrSignatureVerification {
		t.Fatalf("expected ErrSignatureVerification, got: %v", err)
	}

	// 5. Schema version mismatch
	badSchemaProf := *prof
	badSchemaProf.Version = 2
	if err := badSchemaProf.ValidateNode(node, now); err != ErrInvalidProfileSchema {
		t.Fatalf("expected ErrInvalidProfileSchema, got: %v", err)
	}
}

func TestCertificateFingerprintVerification(t *testing.T) {
	certDER := []byte("dummy-tls-certificate-der-bytes")
	sum := sha256.Sum256(certDER)
	expectedHex := hex.EncodeToString(sum[:])

	if err := VerifyCertificateFingerprint(certDER, expectedHex); err != nil {
		t.Fatalf("expected fingerprint match, got: %v", err)
	}

	// Mismatched fingerprint fails
	badHex := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifyCertificateFingerprint(certDER, badHex); err == nil {
		t.Fatal("expected fingerprint mismatch error, got nil")
	}

	// Empty fingerprint allows bypass (e.g. Let's Encrypt rotation)
	if err := VerifyCertificateFingerprint(certDER, ""); err != nil {
		t.Fatalf("expected empty fingerprint to be allowed, got: %v", err)
	}
}

func TestVPSProfilePersistenceAndSelfHealing(t *testing.T) {
	tempDir := t.TempDir()
	testFilePath := filepath.Join(tempDir, "vps_profile.json")

	// Save valid profile
	prof := DefaultVPSProfile()
	prof.Nodes["test-node"] = VPSProfileNode{
		NodeID:          "test-node",
		ActivePort:      2083,
		ActiveTransport: "quic",
		SNI:             "node.test.local",
		ExpiresAt:       time.Now().Unix() + 3600,
	}

	if err := saveVPSProfileLocked(testFilePath, prof); err != nil {
		t.Fatalf("save profile: %v", err)
	}

	// Verify loaded
	loaded := loadVPSProfileLocked(testFilePath)
	if loaded == nil || len(loaded.Nodes) != 1 {
		t.Fatalf("failed to load valid profile: %+v", loaded)
	}

	// Corrupt file contents to test self-healing
	if err := os.WriteFile(testFilePath, []byte("{broken-json..."), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	healed := loadVPSProfileLocked(testFilePath)
	if healed == nil || healed.Version != VPSProfileVersion {
		t.Fatalf("self-healing failed, expected default profile: %+v", healed)
	}

	// Verify corrupt backup was generated
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("read tempDir: %v", err)
	}

	foundCorruptBackup := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			continue
		}
		if len(entry.Name()) > len("vps_profile.json.corrupt") {
			foundCorruptBackup = true
			break
		}
	}

	if !foundCorruptBackup {
		t.Fatal("expected corrupt profile backup file to exist")
	}
}
