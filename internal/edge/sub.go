// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ==========================================
// 1. Subscription Types & Data Models
// ==========================================

// SubDocument represents the native aero/2.0 subscription document
type SubDocument struct {
	Version   string      `json:"version"`
	UserID    string      `json:"userId,omitempty"`
	ExpireAt  int64       `json:"expireAt,omitempty"`
	Signature string      `json:"signature,omitempty"`
	Servers   []SubServer `json:"servers"`
	CreatedAt int64       `json:"createdAt,omitempty"`
}

// SubServer represents a single edge node entry in subscription
type SubServer struct {
	Name     string   `json:"name"`
	Address  string   `json:"address"`
	Token    string   `json:"token"`
	SNI      string   `json:"sni"`
	Protocol string   `json:"protocol"`
	PinSPKI  []string `json:"pin_spki,omitempty"`
}

// UserSub represents a user-specific subscription (e.g. /sub/username{6-char-code})
type UserSub struct {
	Username  string      `json:"username"`
	Slug      string      `json:"slug"`      // e.g. jacky123456
	Token     string      `json:"token"`     // user token
	ExpireAt  int64       `json:"expireAt"`  // unix epoch seconds
	Servers   []SubServer `json:"servers"`   // nodes allocated to user
	Signature string      `json:"signature"` // verification signature
	CreatedAt int64       `json:"createdAt"` // creation timestamp
}

// IsExpired returns true if the user subscription has expired
func (u *UserSub) IsExpired() bool {
	if u.ExpireAt <= 0 {
		return false
	}
	return time.Now().Unix() > u.ExpireAt
}

// SubMeta holds on-disk subscription metadata
type SubMeta struct {
	Secret   string             `json:"secret"`
	Document SubDocument        `json:"document"`
	UserSubs map[string]UserSub `json:"user_subs,omitempty"`
}

// EnsureSubParams contains parameters for bootstrapping subscription
type EnsureSubParams struct {
	Name    string
	Address string
	Token   string
	SNI     string
	PinSPKI []string
}

// ==========================================
// 2. Subscription Store (sub_meta.json & client-sub.json)
// ==========================================

// SubStore manages sub_meta.json and client-sub.json on disk
type SubStore struct {
	mu   sync.RWMutex
	dir  string
	meta SubMeta
}

// NewSubStore initializes or loads subscription store from dir
func NewSubStore(dir string) (*SubStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("empty data dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &SubStore{dir: dir}
	path := s.metaPath()
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &s.meta); err != nil {
			return nil, fmt.Errorf("parse sub meta: %w", err)
		}
		if s.meta.UserSubs == nil {
			s.meta.UserSubs = make(map[string]UserSub)
		}
		return s, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	s.meta.UserSubs = make(map[string]UserSub)
	return s, nil
}

func (s *SubStore) metaPath() string { return filepath.Join(s.dir, "sub_meta.json") }

// Ensure ensures secret exists, updates default server, and persists both sub_meta.json and client-sub.json
func (s *SubStore) Ensure(p EnsureSubParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.Name == "" {
		p.Name = "default"
	}
	if p.SNI == "" {
		p.SNI = "localhost"
	}

	srv := SubServer{
		Name:     p.Name,
		Address:  p.Address,
		Token:    p.Token,
		SNI:      p.SNI,
		Protocol: "quic",
		PinSPKI:  p.PinSPKI,
	}

	if s.meta.Secret == "" {
		sec, err := randomHexSecret(16)
		if err != nil {
			return err
		}
		s.meta.Secret = sec
	}

	doc := SubDocument{
		Version:   "aero/2.0",
		CreatedAt: time.Now().Unix(),
		Servers:   []SubServer{srv},
	}
	// Sign document with HMAC-SHA256(token)
	doc.Signature = SignSub(doc, []byte(p.Token))
	s.meta.Document = doc

	if err := s.saveLocked(); err != nil {
		return err
	}
	return s.writeClientSubLocked()
}

func (s *SubStore) saveLocked() error {
	data, err := json.MarshalIndent(s.meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.metaPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.metaPath())
}

func (s *SubStore) writeClientSubLocked() error {
	data, err := json.MarshalIndent(s.meta.Document, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "client-sub.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Secret returns the node subscription secret
func (s *SubStore) Secret() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.meta.Secret
}

// Dir returns the data directory
func (s *SubStore) Dir() string { return s.dir }

// DocumentJSON returns JSON bytes of the default subscription
func (s *SubStore) DocumentJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.meta.Document)
}

// Document returns copy of default subscription document
func (s *SubStore) Document() SubDocument {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.meta.Document
}

// UpsertUserSub adds or updates a user-specific subscription
func (s *SubStore) UpsertUserSub(sub UserSub) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta.UserSubs == nil {
		s.meta.UserSubs = make(map[string]UserSub)
	}
	if sub.Slug == "" {
		return fmt.Errorf("empty slug")
	}
	if sub.CreatedAt == 0 {
		sub.CreatedAt = time.Now().Unix()
	}
	// If no specific servers assigned, inherit default server and replace token
	if len(sub.Servers) == 0 && len(s.meta.Document.Servers) > 0 {
		defaultSrv := s.meta.Document.Servers[0]
		defaultSrv.Token = sub.Token
		sub.Servers = []SubServer{defaultSrv}
	}

	doc := SubDocument{
		Version:   "aero/2.0",
		UserID:    sub.Username,
		ExpireAt:  sub.ExpireAt,
		Servers:   sub.Servers,
		CreatedAt: sub.CreatedAt,
	}
	if sub.Token != "" {
		sub.Signature = SignSub(doc, []byte(sub.Token))
	}
	s.meta.UserSubs[sub.Slug] = sub
	return s.saveLocked()
}

// GetUserSub retrieves a user subscription by slug
func (s *SubStore) GetUserSub(slug string) (UserSub, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.meta.UserSubs == nil {
		return UserSub{}, false
	}
	sub, ok := s.meta.UserSubs[slug]
	return sub, ok
}

// ListUserSubs lists all user subscriptions
func (s *SubStore) ListUserSubs() []UserSub {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserSub, 0, len(s.meta.UserSubs))
	for _, sub := range s.meta.UserSubs {
		out = append(out, sub)
	}
	return out
}

// DeleteUserSub deletes a user subscription by slug
func (s *SubStore) DeleteUserSub(slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta.UserSubs == nil {
		return nil
	}
	delete(s.meta.UserSubs, slug)
	return s.saveLocked()
}

// UserDocumentJSON formats a UserSub into subscription JSON
func (s *SubStore) UserDocumentJSON(sub UserSub) ([]byte, error) {
	doc := SubDocument{
		Version:   "aero/2.0",
		UserID:    sub.Username,
		ExpireAt:  sub.ExpireAt,
		Signature: sub.Signature,
		Servers:   sub.Servers,
		CreatedAt: sub.CreatedAt,
	}
	return json.Marshal(doc)
}

// ==========================================
// 3. Subscription Signing & Verification
// ==========================================

type subSignBody struct {
	Version   string      `json:"version"`
	UserID    string      `json:"userId,omitempty"`
	ExpireAt  int64       `json:"expireAt,omitempty"`
	Servers   []SubServer `json:"servers"`
	CreatedAt int64       `json:"createdAt,omitempty"`
}

// SignSub creates HMAC-SHA256 signature encoded as base64 URL-safe
func SignSub(doc SubDocument, key []byte) string {
	body := subSignBody{
		Version:   doc.Version,
		UserID:    doc.UserID,
		ExpireAt:  doc.ExpireAt,
		Servers:   doc.Servers,
		CreatedAt: doc.CreatedAt,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifySub verifies HMAC-SHA256 signature
func VerifySub(doc SubDocument, key []byte) bool {
	if doc.Signature == "" || len(key) == 0 {
		return false
	}
	expected := SignSub(doc, key)
	return hmac.Equal([]byte(expected), []byte(doc.Signature))
}

func randomHexSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ExtractSPKIPin extracts SPKI SHA-256 base64 pin from TLS certificate
func ExtractSPKIPin(cert *tls.Certificate) (string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", fmt.Errorf("empty certificate")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// ==========================================
// 4. HTTP Subscription Handler (/sub/*)
// ==========================================

// SubHandler serves subscription endpoints
type SubHandler struct {
	Store *SubStore
}

// TryServe handles GET /sub/{secret}
func (h *SubHandler) TryServe(w http.ResponseWriter, r *http.Request) bool {
	if h == nil || h.Store == nil {
		return false
	}
	path := r.URL.Path
	if !strings.HasPrefix(path, "/sub/") {
		return false
	}
	secret := strings.TrimPrefix(path, "/sub/")
	secret = strings.Trim(secret, "/")
	if secret == "" || strings.Contains(secret, "/") {
		http.NotFound(w, r)
		return true
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}

	// 1. Check user slug (/sub/{username}{6random})
	if userSub, found := h.Store.GetUserSub(secret); found {
		if userSub.IsExpired() {
			http.Error(w, "subscription expired", http.StatusForbidden)
			return true
		}
		body, err := h.Store.UserDocumentJSON(userSub)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return true
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
		return true
	}

	// 2. Check admin sub (/sub/superadmin) or node secret (/sub/{secret})
	if secret != "superadmin" && secret != h.Store.Secret() {
		http.NotFound(w, r)
		return true
	}
	body, err := h.Store.DocumentJSON()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}

// BootstrapSubscription ensures data directory, updates sub_meta.json, writes client-sub.json, and returns SubStore
func BootstrapSubscription(dir, advertiseHost string, tlsPort int, token, sni string, cert *tls.Certificate) (*SubStore, string, error) {
	if dir == "" {
		dir = "./data"
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}
	store, err := NewSubStore(absDir)
	if err != nil {
		return nil, "", err
	}

	host := strings.TrimSpace(advertiseHost)
	if host == "" || host == "cdn-aero.com" || host == "localhost" {
		host = "127.0.0.1"
	}
	if tlsPort <= 0 {
		tlsPort = 443
	}
	addr := fmt.Sprintf("%s:%d", host, tlsPort)

	var pins []string
	if cert != nil {
		if pin, err := ExtractSPKIPin(cert); err == nil && pin != "" {
			pins = []string{pin}
		}
	}

	if err := store.Ensure(EnsureSubParams{
		Name:    "default",
		Address: addr,
		Token:   token,
		SNI:     sni,
		PinSPKI: pins,
	}); err != nil {
		return nil, "", err
	}

	return store, absDir, nil
}
