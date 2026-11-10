// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	VPSProfileSchemaURL = "https://aero-protocol.com/schemas/vps_profile_v1.json"
	VPSProfileVersion   = 1
	DefaultPubKeyID     = "edge-root-2026"
)

var (
	ErrInvalidProfileSchema   = errors.New("invalid VPS profile schema or version")
	ErrNodeExpired            = errors.New("VPS profile node has expired")
	ErrInvalidNodePort        = errors.New("VPS profile node port out of range (1-65535)")
	ErrMissingPubKeyID        = errors.New("VPS profile node signature specified but pubkey_id missing")
	ErrUnknownPubKeyID        = errors.New("unrecognized pubkey_id")
	ErrInvalidSignatureFormat = errors.New("invalid signature format (hex required)")
	ErrSignatureVerification  = errors.New("Ed25519 signature verification failed")
	ErrFingerprintMismatch    = errors.New("certificate fingerprint mismatch")
)

// VPSProfileNode represents a single edge node's security profile.
type VPSProfileNode struct {
	NodeID                string `json:"node_id"`
	ActivePort            int    `json:"active_port"`
	ActiveTransport       string `json:"active_transport"`
	SNI                   string `json:"sni"`
	ETag                  string `json:"etag,omitempty"`
	LastVerified          int64  `json:"last_verified"`
	RTTMs                 int64  `json:"rtt_ms"`
	CertFingerprintSHA256 string `json:"cert_fingerprint_sha256,omitempty"`
	PubKeyID              string `json:"pubkey_id,omitempty"`
	SignatureEd25519      string `json:"signature_ed25519,omitempty"`
	ExpiresAt             int64  `json:"expires_at"`
}

// VPSProfile is the Schema v1 persisted configuration for verified nodes.
type VPSProfile struct {
	Schema    string                    `json:"$schema,omitempty"`
	Version   int                       `json:"version"`
	UpdatedAt int64                     `json:"updated_at"`
	Nodes     map[string]VPSProfileNode `json:"nodes"`
}

var (
	vpsProfileMu      sync.RWMutex
	trustedPublicKeys = make(map[string]ed25519.PublicKey)
	trustedKeysMu     sync.RWMutex
)

// RegisterTrustedRootKey registers or updates an Ed25519 root public key for signature validation.
func RegisterTrustedRootKey(keyID string, pubKey ed25519.PublicKey) {
	if keyID == "" || len(pubKey) != ed25519.PublicKeySize {
		return
	}
	trustedKeysMu.Lock()
	defer trustedKeysMu.Unlock()
	trustedPublicKeys[keyID] = append(ed25519.PublicKey(nil), pubKey...)
}

// GetTrustedRootKey retrieves a trusted public key by key ID.
func GetTrustedRootKey(keyID string) (ed25519.PublicKey, bool) {
	trustedKeysMu.RLock()
	defer trustedKeysMu.RUnlock()
	k, ok := trustedPublicKeys[keyID]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), k...), true
}

func vpsProfilePath() string {
	return filepath.Join(GetDataDir(), "vps_profile.json")
}

func vpsProfileLockPath() string {
	return filepath.Join(GetDataDir(), "vps_profile.json.lock")
}

// NodeSignPayload returns the canonical bytes to sign or verify for a node.
func NodeSignPayload(n VPSProfileNode) []byte {
	return []byte(fmt.Sprintf("%s|%d|%s|%s|%d", n.NodeID, n.ActivePort, n.ActiveTransport, n.SNI, n.ExpiresAt))
}

// SignVPSProfileNode signs a node's canonical payload using an Ed25519 private key.
func SignVPSProfileNode(privKey ed25519.PrivateKey, node *VPSProfileNode, pubKeyID string) error {
	if node == nil {
		return errors.New("node is nil")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key size")
	}
	node.PubKeyID = pubKeyID
	payload := NodeSignPayload(*node)
	sig := ed25519.Sign(privKey, payload)
	node.SignatureEd25519 = hex.EncodeToString(sig)
	return nil
}

// ValidateNode executes the 5-step validation contract on a node.
func (p *VPSProfile) ValidateNode(node VPSProfileNode, now int64) error {
	// Step 1: Schema / Version check
	if p.Version != VPSProfileVersion {
		return ErrInvalidProfileSchema
	}

	// Step 2: Expiration check
	if node.ExpiresAt <= now {
		return ErrNodeExpired
	}

	// Step 3: Port validity check (1 - 65535, reject 0 or invalid)
	if node.ActivePort < 1 || node.ActivePort > 65535 {
		return ErrInvalidNodePort
	}

	// Step 4: Digital signature verification (if signed)
	if node.SignatureEd25519 != "" {
		if node.PubKeyID == "" {
			return ErrMissingPubKeyID
		}
		pubKey, ok := GetTrustedRootKey(node.PubKeyID)
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownPubKeyID, node.PubKeyID)
		}
		sigBytes, err := hex.DecodeString(node.SignatureEd25519)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			return ErrInvalidSignatureFormat
		}
		payload := NodeSignPayload(node)
		if !ed25519.Verify(pubKey, payload, sigBytes) {
			return ErrSignatureVerification
		}
	}

	return nil
}

// VerifyCertificateFingerprint validates the TLS certificate SHA-256 fingerprint against the cached profile.
func VerifyCertificateFingerprint(certDER []byte, expectedFingerprintHex string) error {
	if expectedFingerprintHex == "" {
		return nil // Non-blocking if fingerprint not provisioned
	}
	sum := sha256.Sum256(certDER)
	actualHex := hex.EncodeToString(sum[:])
	cleanedExpected := strings.ToLower(strings.TrimSpace(expectedFingerprintHex))
	if subtle.ConstantTimeCompare([]byte(actualHex), []byte(cleanedExpected)) != 1 {
		return fmt.Errorf("%w: expected %s, got %s", ErrFingerprintMismatch, cleanedExpected, actualHex)
	}
	return nil
}

// DefaultVPSProfile returns a safe, minimal in-memory fallback profile.
func DefaultVPSProfile() *VPSProfile {
	return &VPSProfile{
		Schema:    VPSProfileSchemaURL,
		Version:   VPSProfileVersion,
		UpdatedAt: time.Now().Unix(),
		Nodes:     make(map[string]VPSProfileNode),
	}
}

// LoadVPSProfile reads and parses vps_profile.json with self-healing fallback.
func LoadVPSProfile() *VPSProfile {
	vpsProfileMu.Lock()
	defer vpsProfileMu.Unlock()

	return loadVPSProfileLocked(vpsProfilePath())
}

func loadVPSProfileLocked(filePath string) *VPSProfile {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultVPSProfile()
		}
		log.Printf("[PROFILE] failed to read profile %s: %v, healing with default", filePath, err)
		healCorruptProfile(filePath)
		return DefaultVPSProfile()
	}

	var prof VPSProfile
	if err := json.Unmarshal(data, &prof); err != nil {
		log.Printf("[PROFILE] corrupt profile JSON %s: %v, healing", filePath, err)
		healCorruptProfile(filePath)
		return DefaultVPSProfile()
	}

	if prof.Version != VPSProfileVersion {
		log.Printf("[PROFILE] unsupported profile version %d, healing", prof.Version)
		healCorruptProfile(filePath)
		return DefaultVPSProfile()
	}

	// Validate nodes and prune any invalid or expired entries
	now := time.Now().Unix()
	validNodes := make(map[string]VPSProfileNode)
	for k, node := range prof.Nodes {
		if err := prof.ValidateNode(node, now); err != nil {
			log.Printf("[PROFILE] node %s validation failed (%v); skipping node", k, err)
			continue
		}
		validNodes[k] = node
	}
	prof.Nodes = validNodes

	return &prof
}

// SaveVPSProfile writes a profile using an independent lock file and atomic rename.
func SaveVPSProfile(p *VPSProfile) error {
	vpsProfileMu.Lock()
	defer vpsProfileMu.Unlock()

	return saveVPSProfileLocked(vpsProfilePath(), p)
}

func saveVPSProfileLocked(filePath string, p *VPSProfile) error {
	if p == nil {
		return errors.New("cannot save nil VPS profile")
	}

	// 1. Acquire independent file lock to prevent multi-process corruption
	lockFile, err := os.OpenFile(vpsProfileLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open profile lock file: %w", err)
	}
	defer lockFile.Close()

	// 2. Prepare payload
	p.Schema = VPSProfileSchemaURL
	p.Version = VPSProfileVersion
	p.UpdatedAt = time.Now().Unix()

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile JSON: %w", err)
	}

	// 3. Write to temporary file in the same directory (L0 §8.8)
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}

	tmpPath := filePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary profile file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temporary profile: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync temporary profile: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temporary profile: %w", err)
	}

	// 4. Atomic Rename to target path
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename profile: %w", err)
	}

	return nil
}

// healCorruptProfile moves a broken profile to vps_profile.json.corrupt.<timestamp>.
func healCorruptProfile(filePath string) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return
	}
	corruptPath := fmt.Sprintf("%s.corrupt.%d", filePath, time.Now().Unix())
	_ = os.Rename(filePath, corruptPath)
	log.Printf("[PROFILE] corrupt profile backed up to %s", corruptPath)
}
