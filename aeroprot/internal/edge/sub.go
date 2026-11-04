// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type subIPLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rate.Limiter
}

var globalSubIPLimiter = &subIPLimiter{
	buckets: make(map[string]*rate.Limiter),
}

func (l *subIPLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= 1024 {
			for k := range l.buckets {
				delete(l.buckets, k)
				break
			}
		}
		lim = rate.NewLimiter(rate.Every(100*time.Millisecond), 60)
		l.buckets[ip] = lim
	}
	return lim.Allow()
}

// ==========================================
// 1. Subscription Types & Data Models
// ==========================================

// SubDocument represents the native aero/3.0 subscription document
type SubDocument struct {
	Version           string      `json:"version"`
	UserID            string      `json:"userId,omitempty"`
	ExpireAt          int64       `json:"expireAt,omitempty"`
	TrafficLimitBytes int64       `json:"trafficLimitBytes,omitempty"`
	TrafficUsedBytes  int64       `json:"trafficUsedBytes,omitempty"`
	Signature         string      `json:"signature,omitempty"`
	Servers           []SubServer `json:"servers"`
	CreatedAt         int64       `json:"createdAt,omitempty"`
}

func (s *SubDocument) UnmarshalJSON(data []byte) error {
	type Alias SubDocument
	aux := struct {
		*Alias
		SnakeTrafficLimit int64  `json:"traffic_limit_bytes"`
		CamelTrafficLimit int64  `json:"trafficLimitBytes"`
		SnakeTrafficUsed  int64  `json:"traffic_used_bytes"`
		CamelTrafficUsed  int64  `json:"trafficUsedBytes"`
		SnakeExpireAt     int64  `json:"expire_at"`
		SnakeUserID       string `json:"user_id"`
		SnakeCreatedAt    int64  `json:"created_at"`
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if s.TrafficLimitBytes == 0 {
		if aux.SnakeTrafficLimit != 0 {
			s.TrafficLimitBytes = aux.SnakeTrafficLimit
		} else if aux.CamelTrafficLimit != 0 {
			s.TrafficLimitBytes = aux.CamelTrafficLimit
		}
	}
	if s.TrafficUsedBytes == 0 {
		if aux.SnakeTrafficUsed != 0 {
			s.TrafficUsedBytes = aux.SnakeTrafficUsed
		} else if aux.CamelTrafficUsed != 0 {
			s.TrafficUsedBytes = aux.CamelTrafficUsed
		}
	}
	if s.ExpireAt == 0 && aux.SnakeExpireAt != 0 {
		s.ExpireAt = aux.SnakeExpireAt
	}
	if s.UserID == "" && aux.SnakeUserID != "" {
		s.UserID = aux.SnakeUserID
	}
	if s.CreatedAt == 0 && aux.SnakeCreatedAt != 0 {
		s.CreatedAt = aux.SnakeCreatedAt
	}
	return nil
}

// SubServer represents a single edge node entry in subscription
type SubServer struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Address     string   `json:"address,omitempty"`
	IP          string   `json:"ip,omitempty"`
	Token       string   `json:"token"`
	SNI         string   `json:"sni"`
	Protocol    string   `json:"protocol"`
	PinSPKI     []string `json:"pin_spki,omitempty"`
	LineType    string   `json:"line_type,omitempty"`
	ISPAffinity string   `json:"isp_affinity,omitempty"`
	AltPorts    []int    `json:"alt_ports,omitempty"`
	ECH         string   `json:"ech,omitempty" yaml:"ech"`
	ECHConfig   string   `json:"ech_config,omitempty" yaml:"ech_config"`
}

func (s *SubServer) UnmarshalJSON(data []byte) error {
	type Alias SubServer
	aux := struct {
		*Alias
		LegacyECHConfig string `json:"echConfig"`
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if s.ECHConfig == "" && aux.LegacyECHConfig != "" {
		s.ECHConfig = aux.LegacyECHConfig
	}
	if s.ECH == "" && s.ECHConfig != "" {
		s.ECH = s.ECHConfig
	}
	if s.ECHConfig == "" && s.ECH != "" {
		s.ECHConfig = s.ECH
	}
	return nil
}

// UserSub represents a user-specific subscription (e.g. /sub/username{6-char-code})
type UserSub struct {
	Username          string      `json:"username"`
	Slug              string      `json:"slug"`     // e.g. jacky123456
	Token             string      `json:"token"`    // user token
	ExpireAt          int64       `json:"expireAt"` // unix epoch seconds
	TrafficLimitBytes int64       `json:"trafficLimitBytes,omitempty"`
	TrafficUsedBytes  int64       `json:"trafficUsedBytes,omitempty"`
	Servers           []SubServer `json:"servers"`   // nodes allocated to user
	Signature         string      `json:"signature"` // verification signature
	CreatedAt         int64       `json:"createdAt"` // creation timestamp
}

func (u *UserSub) UnmarshalJSON(data []byte) error {
	type Alias UserSub
	aux := struct {
		*Alias
		SnakeTrafficLimit int64 `json:"traffic_limit_bytes"`
		CamelTrafficLimit int64 `json:"trafficLimitBytes"`
		SnakeTrafficUsed  int64 `json:"traffic_used_bytes"`
		CamelTrafficUsed  int64 `json:"trafficUsedBytes"`
		SnakeExpireAt     int64 `json:"expire_at"`
		SnakeCreatedAt    int64 `json:"created_at"`
	}{
		Alias: (*Alias)(u),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if u.TrafficLimitBytes == 0 {
		if aux.SnakeTrafficLimit != 0 {
			u.TrafficLimitBytes = aux.SnakeTrafficLimit
		} else if aux.CamelTrafficLimit != 0 {
			u.TrafficLimitBytes = aux.CamelTrafficLimit
		}
	}
	if u.TrafficUsedBytes == 0 {
		if aux.SnakeTrafficUsed != 0 {
			u.TrafficUsedBytes = aux.SnakeTrafficUsed
		} else if aux.CamelTrafficUsed != 0 {
			u.TrafficUsedBytes = aux.CamelTrafficUsed
		}
	}
	if u.ExpireAt == 0 && aux.SnakeExpireAt != 0 {
		u.ExpireAt = aux.SnakeExpireAt
	}
	if u.CreatedAt == 0 && aux.SnakeCreatedAt != 0 {
		u.CreatedAt = aux.SnakeCreatedAt
	}
	return nil
}

// IsExpired returns true if the user subscription has expired
func (u *UserSub) IsExpired() bool {
	if u.ExpireAt <= 0 {
		return false
	}
	return time.Now().Unix() > u.ExpireAt
}

// IsTrafficExceeded returns true if the user has reached or exceeded traffic quota
func (u *UserSub) IsTrafficExceeded() bool {
	if u.TrafficLimitBytes <= 0 {
		return false
	}
	return u.TrafficUsedBytes >= u.TrafficLimitBytes
}

// SubMeta holds on-disk subscription metadata
type SubMeta struct {
	Secret   string             `json:"secret"`
	Document SubDocument        `json:"document"`
	UserSubs map[string]UserSub `json:"user_subs,omitempty"`
}

// EnsureSubParams contains parameters for bootstrapping subscription
type EnsureSubParams struct {
	Name        string
	Host        string
	Address     string
	IP          string
	Token       string
	SNI         string
	PinSPKI     []string
	LineType    string
	ISPAffinity string
	AltPorts    []int
	ECH         string
	ECHConfig   string
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

	host := p.Host
	if host == "" {
		host = p.Address
	}
	var primaryPort int
	if h, portStr, err := net.SplitHostPort(host); err == nil {
		if pNum, err := strconv.Atoi(portStr); err == nil && pNum > 0 {
			primaryPort = pNum
		}
		if portStr == "443" || portStr == "" {
			host = h
		}
	}
	if primaryPort <= 0 && p.Address != "" {
		if _, portStr, err := net.SplitHostPort(p.Address); err == nil {
			if pNum, err := strconv.Atoi(portStr); err == nil && pNum > 0 {
				primaryPort = pNum
			}
		}
	}
	if primaryPort <= 0 {
		primaryPort = 443
	}

	altPorts := p.AltPorts
	if len(altPorts) == 0 {
		candidates := StandardCandidatePorts
		if primaryPort == 443 {
			altPorts = append([]int(nil), candidates...)
		} else {
			altPorts = []int{443}
			for _, cp := range candidates {
				if cp != primaryPort {
					altPorts = append(altPorts, cp)
				}
			}
		}
	} else {
		filtered := make([]int, 0, len(altPorts))
		seen := make(map[int]bool)
		for _, cp := range altPorts {
			if cp > 0 && cp != primaryPort && !seen[cp] {
				seen[cp] = true
				filtered = append(filtered, cp)
			}
		}
		altPorts = filtered
	}

	ip := p.IP
	if ip == "" {
		if parsed := net.ParseIP(host); parsed != nil && parsed.To4() != nil {
			ip = parsed.String()
		}
	}

	echVal := strings.TrimSpace(p.ECHConfig)
	if echVal == "" {
		echVal = strings.TrimSpace(p.ECH)
	}
	if echVal == "" && len(s.meta.Document.Servers) > 0 {
		if s.meta.Document.Servers[0].ECHConfig != "" {
			echVal = s.meta.Document.Servers[0].ECHConfig
		} else {
			echVal = s.meta.Document.Servers[0].ECH
		}
	}

	srvAddr := p.Address
	if primaryPort == 443 {
		if h, _, err := net.SplitHostPort(srvAddr); err == nil {
			srvAddr = h
		} else if strings.HasSuffix(srvAddr, ":443") {
			srvAddr = strings.TrimSuffix(srvAddr, ":443")
		}
	}

	srv := SubServer{
		Name:        p.Name,
		Host:        host,
		Address:     srvAddr,
		IP:          ip,
		Token:       p.Token,
		SNI:         p.SNI,
		Protocol:    "connect-ip",
		PinSPKI:     p.PinSPKI,
		LineType:    p.LineType,
		ISPAffinity: p.ISPAffinity,
		AltPorts:    altPorts,
		ECH:         echVal,
		ECHConfig:   echVal,
	}

	if s.meta.Secret == "" {
		sec, err := randomHexSecret(16)
		if err != nil {
			return err
		}
		s.meta.Secret = sec
	}

	doc := SubDocument{
		Version:   "aero/3.0",
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
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// UpdatePrimaryPort updates the primary port and recalculates alt_ports in sub metadata & client-sub.json
func (s *SubStore) UpdatePrimaryPort(port int, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.meta.Document.Servers) == 0 {
		return nil
	}
	targetHost := host
	if targetHost == "" {
		targetHost = s.meta.Document.Servers[0].Host
	}
	if targetHost == "" {
		targetHost = s.meta.Document.Servers[0].SNI
	}
	if port == 443 {
		s.meta.Document.Servers[0].Address = targetHost
	} else {
		s.meta.Document.Servers[0].Address = net.JoinHostPort(targetHost, strconv.Itoa(port))
	}

	candidates := StandardCandidatePorts
	altPorts := []int{443}
	if port == 443 {
		altPorts = append([]int(nil), candidates...)
	} else {
		for _, cp := range candidates {
			if cp != port {
				altPorts = append(altPorts, cp)
			}
		}
	}
	s.meta.Document.Servers[0].AltPorts = altPorts

	if err := s.saveLocked(); err != nil {
		return err
	}
	return s.writeClientSubLocked()
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

// GetECH returns the current ECH configuration from the default server.
func (s *SubStore) GetECH() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.meta.Document.Servers) > 0 {
		if s.meta.Document.Servers[0].ECHConfig != "" {
			return s.meta.Document.Servers[0].ECHConfig
		}
		return s.meta.Document.Servers[0].ECH
	}
	return ""
}

// SetECH updates the ECH configuration on the default server, re-signs the document, and persists.
func (s *SubStore) SetECH(ech string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.meta.Document.Servers) == 0 {
		s.meta.Document.Servers = []SubServer{{
			Name:      "default",
			Protocol:  "connect-ip",
			ECH:       ech,
			ECHConfig: ech,
		}}
	} else {
		s.meta.Document.Servers[0].ECH = ech
		s.meta.Document.Servers[0].ECHConfig = ech
		if s.meta.Document.Servers[0].Token != "" {
			s.meta.Document.Signature = SignSub(s.meta.Document, []byte(s.meta.Document.Servers[0].Token))
		}
	}
	if err := s.saveLocked(); err != nil {
		return err
	}
	return s.writeClientSubLocked()
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
	// If existing user already has accumulated TrafficUsedBytes and new sub has 0, preserve usage unless explicitly passed
	if existing, exists := s.meta.UserSubs[sub.Slug]; exists {
		if sub.TrafficUsedBytes == 0 && existing.TrafficUsedBytes > 0 {
			sub.TrafficUsedBytes = existing.TrafficUsedBytes
		}
	}
	// If no specific servers assigned, inherit default server and replace token
	if len(sub.Servers) == 0 && len(s.meta.Document.Servers) > 0 {
		defaultSrv := s.meta.Document.Servers[0]
		defaultSrv.Token = sub.Token
		sub.Servers = []SubServer{defaultSrv}
	}

	doc := SubDocument{
		Version:           "aero/3.0",
		UserID:            sub.Username,
		ExpireAt:          sub.ExpireAt,
		TrafficLimitBytes: sub.TrafficLimitBytes,
		TrafficUsedBytes:  sub.TrafficUsedBytes,
		Servers:           sub.Servers,
		CreatedAt:         sub.CreatedAt,
	}
	if sub.Token != "" {
		sub.Signature = SignSub(doc, []byte(sub.Token))
	}
	s.meta.UserSubs[sub.Slug] = sub
	return s.saveLocked()
}

// RecordTraffic adds used bytes to a user subscription's TrafficUsedBytes
func (s *SubStore) RecordTraffic(slug string, bytes int64) error {
	if bytes <= 0 || slug == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta.UserSubs == nil {
		return nil
	}
	sub, exists := s.meta.UserSubs[slug]
	if !exists {
		return nil
	}
	sub.TrafficUsedBytes += bytes
	s.meta.UserSubs[slug] = sub
	return s.saveLocked()
}

// AdminDocument returns the dedicated admin subscription document with permanent validity and unlimited quota
func (s *SubStore) AdminDocument() SubDocument {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc := s.meta.Document
	doc.UserID = "admin"
	doc.ExpireAt = 0          // permanent validity
	doc.TrafficLimitBytes = 0 // unlimited traffic
	doc.TrafficUsedBytes = 0
	primaryToken := ""
	if len(doc.Servers) > 0 {
		primaryToken = doc.Servers[0].Token
	}
	if primaryToken != "" {
		doc.Signature = SignSub(doc, []byte(primaryToken))
	}
	return doc
}

// AdminDocumentJSON formats the admin subscription document into JSON
func (s *SubStore) AdminDocumentJSON() ([]byte, error) {
	doc := s.AdminDocument()
	return json.Marshal(doc)
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
	servers := sub.Servers
	if len(servers) == 0 {
		s.mu.RLock()
		servers = s.meta.Document.Servers
		s.mu.RUnlock()
	}
	if sub.Token != "" && len(servers) > 0 {
		userServers := make([]SubServer, len(servers))
		copy(userServers, servers)
		for i := range userServers {
			userServers[i].Token = sub.Token
		}
		servers = userServers
	}
	doc := SubDocument{
		Version:           "aero/3.0",
		UserID:            sub.Username,
		ExpireAt:          sub.ExpireAt,
		TrafficLimitBytes: sub.TrafficLimitBytes,
		TrafficUsedBytes:  sub.TrafficUsedBytes,
		Signature:         sub.Signature,
		Servers:           servers,
		CreatedAt:         sub.CreatedAt,
	}
	return json.Marshal(doc)
}

// ==========================================
// 3. Subscription Signing & Verification
// ==========================================

type subSignBody struct {
	Version           string      `json:"version"`
	UserID            string      `json:"userId,omitempty"`
	ExpireAt          int64       `json:"expireAt,omitempty"`
	TrafficLimitBytes int64       `json:"trafficLimitBytes,omitempty"`
	TrafficUsedBytes  int64       `json:"trafficUsedBytes,omitempty"`
	Servers           []SubServer `json:"servers"`
	CreatedAt         int64       `json:"createdAt,omitempty"`
}

// SignSub creates HMAC-SHA256 signature encoded as base64 URL-safe
func SignSub(doc SubDocument, key []byte) string {
	body := subSignBody{
		Version:           doc.Version,
		UserID:            doc.UserID,
		ExpireAt:          doc.ExpireAt,
		TrafficLimitBytes: doc.TrafficLimitBytes,
		Servers:           doc.Servers,
		CreatedAt:         doc.CreatedAt,
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

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if !globalSubIPLimiter.allow(clientIP) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return true
	}

	secret := strings.TrimPrefix(path, "/sub/")
	secret = strings.Trim(secret, "/")
	if secret == "" || strings.Contains(secret, "/") || strings.Contains(secret, "..") || strings.Contains(secret, "\\") {
		http.NotFound(w, r)
		return true
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}

	// 1. Intercept dedicated /sub/admin returning permanent validity & unlimited quota
	if secret == "admin" {
		body, err := h.Store.AdminDocumentJSON()
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

	// 2. Check user slug (/sub/{username}{6random})
	if userSub, found := h.Store.GetUserSub(secret); found {
		if userSub.IsExpired() {
			http.Error(w, "subscription expired", http.StatusForbidden)
			return true
		}
		if userSub.IsTrafficExceeded() {
			http.Error(w, "traffic limit exceeded", http.StatusForbidden)
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

	// 3. Check node secret (/sub/{secret}) with constant-time comparison (SEC-10)
	if subtle.ConstantTimeCompare([]byte(secret), []byte(h.Store.Secret())) != 1 {
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
func BootstrapSubscription(cfg ServerConfig, cert *tls.Certificate) (*SubStore, string, error) {
	dir := cfg.DataDir
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

	host := strings.TrimSpace(cfg.AdvertiseHost)
	if host == "" {
		host = cfg.Domain
	}
	if host == "" || host == "cdn-aero.com" || host == "localhost" {
		host = "127.0.0.1"
	}
	tlsPort := 443
	if cfg.Listen != "" {
		if _, portStr, err := net.SplitHostPort(cfg.Listen); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
				tlsPort = p
			}
		}
	}
	var addr string
	if tlsPort == 443 || tlsPort <= 0 {
		addr = host
	} else {
		addr = fmt.Sprintf("%s:%d", host, tlsPort)
	}

	sni := cfg.Domain
	if sni == "" {
		sni = "localhost"
	}

	var pins []string
	if cert != nil {
		if pin, err := ExtractSPKIPin(cert); err == nil && pin != "" {
			pins = []string{pin}
		}
	}

	altPorts := cfg.AltPorts
	if len(altPorts) == 0 && len(cfg.AltListenPorts) > 0 {
		altPorts = append([]int(nil), cfg.AltListenPorts...)
	}

	if err := store.Ensure(EnsureSubParams{
		Name:        "default",
		Address:     addr,
		IP:          cfg.IP,
		Token:       cfg.Token,
		SNI:         sni,
		PinSPKI:     pins,
		LineType:    cfg.LineType,
		ISPAffinity: cfg.ISPAffinity,
		AltPorts:    altPorts,
		ECH:         cfg.ECH,
	}); err != nil {
		return nil, "", err
	}

	return store, absDir, nil
}

// FormatZeroPortSubURL formats clean zero-port URL: https://{host}/sub/{slug}
func FormatZeroPortSubURL(domainOrHost, slug string) string {
	raw := strings.TrimSpace(domainOrHost)
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	if raw == "" {
		raw = "127.0.0.1"
	}
	if ip := net.ParseIP(raw); ip != nil && ip.To4() == nil {
		raw = "[" + raw + "]"
	}
	cleanSlug := strings.TrimPrefix(slug, "/")
	return fmt.Sprintf("https://%s/sub/%s", raw, cleanSlug)
}

// ExtractSPKIPinFromCert extracts SPKI SHA-256 base64 pin directly from parsed x509.Certificate
func ExtractSPKIPinFromCert(parsed *x509.Certificate) string {
	if parsed == nil {
		return ""
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
