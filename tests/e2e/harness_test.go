// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// StandardCandidatePorts represents the authoritative global candidate port contract.
var StandardCandidatePorts = []int{2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443}

// Wire contract models

type SubDocument struct {
	Version           string      `json:"version"`
	UserID            string      `json:"userId,omitempty"`
	ExpireAt          int64       `json:"expireAt,omitempty"`
	TrafficLimitBytes int64       `json:"trafficLimitBytes,omitempty"`
	Signature         string      `json:"signature,omitempty"`
	Servers           []SubServer `json:"servers"`
	CreatedAt         int64       `json:"createdAt,omitempty"`
}

type SubServer struct {
	Name        string   `json:"name"`
	Host        string   `json:"host,omitempty"`
	Address     string   `json:"address"`
	IP          string   `json:"ip,omitempty"`
	Token       string   `json:"token"`
	SNI         string   `json:"sni"`
	Protocol    string   `json:"protocol"`
	PinSPKI     []string `json:"pin_spki,omitempty"`
	LineType    string   `json:"line_type,omitempty"`
	ISPAffinity string   `json:"isp_affinity,omitempty"`
	AltPorts    []int    `json:"alt_ports,omitempty"`
	ECH         string   `json:"ech,omitempty"`
	ECHConfig   string   `json:"ech_config,omitempty"`
}

func (s *SubServer) UnmarshalJSON(data []byte) error {
	type Alias SubServer
	aux := struct {
		*Alias
		LegacyISPAffinity string `json:"ispAffinity"`
		LegacyLineType    string `json:"lineType"`
		LegacyAltPorts    []int  `json:"altPorts"`
		LegacyECHConfig   string `json:"echConfig"`
		LegacyECH         string `json:"ech"`
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if s.ISPAffinity == "" && aux.LegacyISPAffinity != "" {
		s.ISPAffinity = aux.LegacyISPAffinity
	}
	if s.LineType == "" && aux.LegacyLineType != "" {
		s.LineType = aux.LegacyLineType
	}
	if len(s.AltPorts) == 0 && len(aux.LegacyAltPorts) > 0 {
		s.AltPorts = aux.LegacyAltPorts
	}
	if s.ECHConfig == "" && aux.LegacyECHConfig != "" {
		s.ECHConfig = aux.LegacyECHConfig
	}
	if s.ECH == "" && aux.LegacyECH != "" {
		s.ECH = aux.LegacyECH
	}
	if s.ECH == "" && s.ECHConfig != "" {
		s.ECH = s.ECHConfig
	}
	if s.ECHConfig == "" && s.ECH != "" {
		s.ECHConfig = s.ECH
	}
	return nil
}

type UserSub struct {
	Username          string      `json:"username"`
	Slug              string      `json:"slug"`
	Token             string      `json:"token"`
	ExpireAt          int64       `json:"expireAt"`
	TrafficLimitBytes int64       `json:"trafficLimitBytes"`
	TrafficUsedBytes  int64       `json:"trafficUsedBytes"`
	Servers           []SubServer `json:"servers"`
	Signature         string      `json:"signature"`
	CreatedAt         int64       `json:"createdAt"`
}

type ConsoleMetrics struct {
	UptimeSeconds   uint64  `json:"uptime_seconds"`
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	MemoryTotalMB   uint64  `json:"memory_total_mb"`
	MemoryUsedMB    uint64  `json:"memory_used_mb"`
	DiskTotalGB     uint64  `json:"disk_total_gb"`
	DiskUsedGB      uint64  `json:"disk_used_gb"`
	NetRxBytes      uint64  `json:"net_rx_bytes"`
	NetTxBytes      uint64  `json:"net_tx_bytes"`
	PurityScore     int     `json:"purity_score"`
	WarpActive      bool    `json:"warp_active"`
}

type CleanlinessReport struct {
	YouTubeCountry string `json:"youtube_country"`
	GoogleHK       bool   `json:"google_hk"`
	GeminiBlocked  bool   `json:"gemini_blocked"`
	Score          int    `json:"score"`
	IsCNMarked     bool   `json:"is_cn_marked"`
}

// HMAC-SHA256 signing for SubDocument

type subSignPayload struct {
	Version           string      `json:"version"`
	UserID            string      `json:"userId,omitempty"`
	ExpireAt          int64       `json:"expireAt,omitempty"`
	TrafficLimitBytes int64       `json:"trafficLimitBytes,omitempty"`
	Servers           []SubServer `json:"servers"`
	CreatedAt         int64       `json:"createdAt,omitempty"`
}

func SignSubDocument(doc SubDocument, key []byte) string {
	payload := subSignPayload{
		Version:           doc.Version,
		UserID:            doc.UserID,
		ExpireAt:          doc.ExpireAt,
		TrafficLimitBytes: doc.TrafficLimitBytes,
		Servers:           doc.Servers,
		CreatedAt:         doc.CreatedAt,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

func VerifySubDocument(doc SubDocument, key []byte) bool {
	if doc.Signature == "" || len(key) == 0 {
		return false
	}
	expected := SignSubDocument(doc, key)
	return hmac.Equal([]byte(expected), []byte(doc.Signature))
}

// SPKI PIN generation and extraction

func ExtractSPKIPinFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// TLS Certificate Generator for testing

type GeneratedCert struct {
	TLSCert    tls.Certificate
	ParsedCert *x509.Certificate
	CertPEM    []byte
	KeyPEM     []byte
	SPKIPin    string
}

func GenerateTestCertificate(dnsName string, org string) (*GeneratedCert, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   dnsName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(dnsName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{dnsName}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	spkiPin := ExtractSPKIPinFromCert(parsed)

	return &GeneratedCert{
		TLSCert:    tlsCert,
		ParsedCert: parsed,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		SPKIPin:    spkiPin,
	}, nil
}

// MockEdgeServer provides an opaque-box HTTP/HTTPS server honoring all AERO Edge specifications.

type MockEdgeOptions struct {
	Domain        string
	AdminKey      string
	ServerToken   string
	DataDir       string
	CertDir       string
	CertFile      string
	KeyFile       string
	UseTLS        bool
	PrimaryPort   int
	AltPorts      []int
	WarpActive    bool
	WarpProxyAddr string
}

type MockEdgeServer struct {
	Opts          MockEdgeOptions
	mu            sync.RWMutex
	userSubs      map[string]*UserSub
	serverToken   string
	adminKey      string
	domain        string
	primaryPort   int
	altPorts      []int
	warpActive    bool
	warpProxyAddr string
	certFile      string
	keyFile       string
	certModTime   time.Time
	cachedCert    *tls.Certificate
	httpServer    *httptest.Server
	requestCount  int64
	metrics       ConsoleMetrics
	purityReport  CleanlinessReport
}

func NewMockEdgeServer(t *testing.T, opts MockEdgeOptions) *MockEdgeServer {
	t.Helper()
	if opts.Domain == "" {
		opts.Domain = "edge.example.com"
	}
	if opts.AdminKey == "" {
		opts.AdminKey = "test_admin_key_999"
	}
	if opts.ServerToken == "" {
		opts.ServerToken = "aero_secret_token_123456"
	}
	if opts.PrimaryPort <= 0 {
		opts.PrimaryPort = 443
	}
	if len(opts.AltPorts) == 0 {
		opts.AltPorts = append([]int(nil), StandardCandidatePorts...)
	}

	m := &MockEdgeServer{
		Opts:          opts,
		userSubs:      make(map[string]*UserSub),
		serverToken:   opts.ServerToken,
		adminKey:      opts.AdminKey,
		domain:        opts.Domain,
		primaryPort:   opts.PrimaryPort,
		altPorts:      opts.AltPorts,
		warpActive:    opts.WarpActive,
		warpProxyAddr: opts.WarpProxyAddr,
		certFile:      opts.CertFile,
		keyFile:       opts.KeyFile,
		metrics: ConsoleMetrics{
			UptimeSeconds:   120,
			CPUUsagePercent: 12.5,
			MemoryTotalMB:   2048,
			MemoryUsedMB:    512,
			DiskTotalGB:     40,
			DiskUsedGB:      15,
			NetRxBytes:      1024000,
			NetTxBytes:      2048000,
			PurityScore:     95,
			WarpActive:      opts.WarpActive,
		},
		purityReport: CleanlinessReport{
			YouTubeCountry: "US",
			GoogleHK:       false,
			GeminiBlocked:  false,
			Score:          95,
			IsCNMarked:     false,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", m.handleHealthz)
	mux.HandleFunc("/health", m.handleHealthz)
	mux.HandleFunc("/sub/admin", m.handleAdminSub)
	mux.HandleFunc("/sub/", m.handleSubSlug)
	mux.HandleFunc("/admin/subs", m.handleAdminSubsAPI)
	mux.HandleFunc("/console", m.handleConsole)
	mux.HandleFunc("/api/metrics", m.handleMetricsAPI)
	mux.HandleFunc("/api/purity", m.handlePurityAPI)
	mux.HandleFunc("/api/warp/toggle", m.handleWarpToggleAPI)

	if opts.UseTLS && opts.CertFile != "" && opts.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err == nil {
			m.cachedCert = &cert
			if fi, err := os.Stat(opts.CertFile); err == nil {
				m.certModTime = fi.ModTime()
			}
		}

		tlsCfg := &tls.Config{
			GetCertificate: m.GetCertificateDynamic,
		}
		s := httptest.NewUnstartedServer(mux)
		s.TLS = tlsCfg
		s.StartTLS()
		m.httpServer = s
	} else {
		m.httpServer = httptest.NewServer(mux)
	}

	return m
}

func (m *MockEdgeServer) Close() {
	if m.httpServer != nil {
		m.httpServer.Close()
	}
}

func (m *MockEdgeServer) URL() string {
	if m.httpServer == nil {
		return ""
	}
	return m.httpServer.URL
}

func (m *MockEdgeServer) Client() *http.Client {
	if m.httpServer != nil {
		return m.httpServer.Client()
	}
	return http.DefaultClient
}

func (m *MockEdgeServer) GetCertificateDynamic(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.certFile == "" || m.keyFile == "" {
		if m.cachedCert != nil {
			return m.cachedCert, nil
		}
		return nil, fmt.Errorf("no cert configured")
	}

	fi, err := os.Stat(m.certFile)
	if err != nil {
		if m.cachedCert != nil {
			return m.cachedCert, nil
		}
		return nil, err
	}

	if m.cachedCert == nil || fi.ModTime().After(m.certModTime) {
		cert, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
		if err != nil {
			if m.cachedCert != nil {
				return m.cachedCert, nil
			}
			return nil, err
		}
		m.cachedCert = &cert
		m.certModTime = fi.ModTime()
	}

	return m.cachedCert, nil
}

func (m *MockEdgeServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (m *MockEdgeServer) handleAdminSub(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&m.requestCount, 1)
	m.mu.RLock()
	defer m.mu.RUnlock()

	server := SubServer{
		Name:        "AERO-Admin-Node",
		Host:        m.domain,
		Address:     m.domain,
		Token:       m.serverToken,
		SNI:         m.domain,
		Protocol:    "connect-ip",
		AltPorts:    append([]int(nil), m.altPorts...),
		LineType:    "native",
		ISPAffinity: "any",
	}

	doc := SubDocument{
		Version:           "aero/3.0",
		UserID:            "admin",
		ExpireAt:          0, // 0 = permanent
		TrafficLimitBytes: 0, // 0 = unlimited
		Servers:           []SubServer{server},
		CreatedAt:         time.Now().Unix(),
	}
	doc.Signature = SignSubDocument(doc, []byte(m.serverToken))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

func (m *MockEdgeServer) handleSubSlug(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&m.requestCount, 1)
	slug := strings.TrimPrefix(r.URL.Path, "/sub/")
	slug = strings.Trim(slug, "/")

	if slug == "" || strings.Contains(slug, "/") || strings.Contains(slug, "..") {
		http.NotFound(w, r)
		return
	}

	m.mu.RLock()
	user, exists := m.userSubs[slug]
	m.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	now := time.Now().Unix()
	if user.ExpireAt > 0 && now > user.ExpireAt {
		http.Error(w, "subscription expired", http.StatusForbidden)
		return
	}

	if user.TrafficLimitBytes > 0 && user.TrafficUsedBytes >= user.TrafficLimitBytes {
		http.Error(w, "traffic limit exceeded", http.StatusForbidden)
		return
	}

	servers := user.Servers
	if len(servers) == 0 {
		servers = []SubServer{{
			Name:        "AERO-" + user.Username,
			Host:        m.domain,
			Address:     m.domain,
			Token:       user.Token,
			SNI:         m.domain,
			Protocol:    "connect-ip",
			AltPorts:    append([]int(nil), m.altPorts...),
			LineType:    "native",
			ISPAffinity: "any",
		}}
	}

	doc := SubDocument{
		Version:           "aero/3.0",
		UserID:            user.Username,
		ExpireAt:          user.ExpireAt,
		TrafficLimitBytes: user.TrafficLimitBytes,
		Servers:           servers,
		CreatedAt:         user.CreatedAt,
	}
	doc.Signature = SignSubDocument(doc, []byte(user.Token))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

func (m *MockEdgeServer) handleAdminSubsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !m.validateAdminAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Username          string `json:"username"`
		Slug              string `json:"slug"`
		Token             string `json:"token"`
		ExpireAt          int64  `json:"expire_at"`
		TrafficLimitBytes int64  `json:"traffic_limit_bytes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Slug == "" {
		http.Error(w, "slug required", http.StatusBadRequest)
		return
	}

	m.UpsertUserSub(UserSub{
		Username:          req.Username,
		Slug:              req.Slug,
		Token:             req.Token,
		ExpireAt:          req.ExpireAt,
		TrafficLimitBytes: req.TrafficLimitBytes,
		CreatedAt:         time.Now().Unix(),
	})

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "slug": req.Slug})
}

func (m *MockEdgeServer) handleConsole(w http.ResponseWriter, r *http.Request) {
	if !m.validateAdminAuth(r) {
		http.Error(w, "forbidden: invalid admin key", http.StatusForbidden)
		return
	}

	html := `<!DOCTYPE html><html><head><title>AERO Edge Console</title></head><body><h1>AERO Console</h1><div id="stats"></div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

func (m *MockEdgeServer) handleMetricsAPI(w http.ResponseWriter, r *http.Request) {
	if !m.validateAdminAuth(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m.metrics)
}

func (m *MockEdgeServer) handlePurityAPI(w http.ResponseWriter, r *http.Request) {
	if !m.validateAdminAuth(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m.purityReport)
}

func (m *MockEdgeServer) handleWarpToggleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !m.validateAdminAuth(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	m.mu.Lock()
	m.warpActive = !m.warpActive
	m.metrics.WarpActive = m.warpActive
	if m.warpActive {
		m.purityReport.Score = 95
		m.metrics.PurityScore = 95
	} else {
		m.purityReport.Score = 70
		m.metrics.PurityScore = 70
	}
	active := m.warpActive
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "warp_active": active})
}

func (m *MockEdgeServer) validateAdminAuth(r *http.Request) bool {
	key := r.URL.Query().Get("key")
	if key == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			key = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			key = r.Header.Get("X-Aero-Admin-Key")
		}
	}
	if key == "" || m.adminKey == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(m.adminKey)) == 1
}

func (m *MockEdgeServer) UpsertUserSub(u UserSub) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userSubs[u.Slug] = &u
}

func (m *MockEdgeServer) RecordTraffic(slug string, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.userSubs[slug]; ok {
		u.TrafficUsedBytes += bytes
	}
}

// Client Ladder Probe Simulator

type LadderProbeResult struct {
	ActivePort  int
	Latency     time.Duration
	ProbedPorts []int
	Err         error
}

func SimulateConcurrentLadderProbe(ctx context.Context, domain string, ports []int, openPort int, portDelay time.Duration) LadderProbeResult {
	type portResponse struct {
		port    int
		latency time.Duration
		err     error
	}

	resultCh := make(chan portResponse, len(ports))
	var wg sync.WaitGroup

	start := time.Now()
	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				resultCh <- portResponse{port: port, err: ctx.Err()}
				return
			case <-time.After(portDelay):
			}

			if port == openPort {
				resultCh <- portResponse{port: port, latency: time.Since(start), err: nil}
			} else {
				resultCh <- portResponse{port: port, err: fmt.Errorf("connection refused on port %d", port)}
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var probed []int
	for resp := range resultCh {
		probed = append(probed, resp.port)
		if resp.err == nil {
			return LadderProbeResult{
				ActivePort:  resp.port,
				Latency:     resp.latency,
				ProbedPorts: probed,
				Err:         nil,
			}
		}
	}

	return LadderProbeResult{
		ActivePort:  0,
		ProbedPorts: probed,
		Err:         errors.New("all candidate ports unreachable"),
	}
}

// STUN Packet Helpers

func BuildSTUNBindingRequest() []byte {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0001)     // Binding Request
	binary.BigEndian.PutUint16(pkt[2:4], 0x0000)     // Message Length = 0
	binary.BigEndian.PutUint32(pkt[4:8], 0x2112A442) // Magic Cookie
	_, _ = rand.Read(pkt[8:20])                      // 12-byte Transaction ID
	return pkt
}

func IsSTUNPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	// Check magic cookie 0x2112A442 at offset 4..8
	cookie := binary.BigEndian.Uint32(data[4:8])
	return cookie == 0x2112A442
}

// DNS Packet Helpers

func BuildDNSQuery(domain string, qtype uint16) []byte {
	var buf bytes.Buffer
	// Transaction ID
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x1234))
	// Flags: Standard query
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0100))
	// QDCOUNT: 1
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	// ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))

	// Labels
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0) // End of domain

	// QTYPE
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	// QCLASS: IN (1)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))

	return buf.Bytes()
}

func SimulateDNSFunnel(queryBytes []byte) (isFakeIP bool, isAAAADropped bool, isDirectCN bool, answerIP net.IP) {
	if len(queryBytes) < 12 {
		return false, false, false, nil
	}

	// Parse domain name
	offset := 12
	var parts []string
	for offset < len(queryBytes) {
		lenByte := int(queryBytes[offset])
		offset++
		if lenByte == 0 {
			break
		}
		if offset+lenByte > len(queryBytes) {
			return false, false, false, nil
		}
		parts = append(parts, string(queryBytes[offset:offset+lenByte]))
		offset += lenByte
	}
	domain := strings.Join(parts, ".")

	if offset+4 > len(queryBytes) {
		return false, false, false, nil
	}
	qtype := binary.BigEndian.Uint16(queryBytes[offset : offset+2])

	// .cn direct passthrough
	if strings.HasSuffix(strings.ToLower(domain), ".cn") {
		if qtype == 28 { // AAAA
			// Drop AAAA for .cn as well
			return false, true, true, nil
		}
		return false, false, true, net.ParseIP("114.114.114.114")
	}

	// Non-.cn AAAA dropping (QTYPE 28 -> Empty NOERROR)
	if qtype == 28 {
		return false, true, false, nil
	}

	// Non-.cn A query (QTYPE 1) -> 198.18 Fake-IP pool
	if qtype == 1 {
		// Return 198.18.0.100
		fakeIP := net.ParseIP("198.18.0.100")
		return true, false, false, fakeIP
	}

	return false, false, false, nil
}

// Node Badge Helpers

func RenderNodeBadges(country string, purityScore int, aiBlocked bool, warpActive bool) string {
	var badges []string
	if country == "US" {
		badges = append(badges, "[🇺🇸 原生]")
	} else if country == "HK" {
		badges = append(badges, "[🇭🇰 原生]")
	} else if country == "JP" {
		badges = append(badges, "[🇯🇵 原生]")
	}

	if !aiBlocked && purityScore >= 80 {
		badges = append(badges, "[✨ Gemini 解锁]")
	}

	if warpActive {
		badges = append(badges, "[🛡️ WARP 接管]")
	}

	return strings.Join(badges, " ")
}

// Script and Repository inspection helpers

func FindProjectRoot(t *testing.T) string {
	t.Helper()
	// Check current working dir
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}

	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find project root containing go.mod from %s", cwd)
	return ""
}

func ReadDeployScript(t *testing.T) string {
	t.Helper()
	root := FindProjectRoot(t)
	scriptPath := filepath.Join(root, "deploy", "edge-install.sh")
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read deploy/edge-install.sh: %v", err)
	}
	return string(data)
}
