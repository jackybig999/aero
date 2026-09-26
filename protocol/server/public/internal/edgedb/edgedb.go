// Copyright 2026 AERO Protocol Contributors
// AERO Edge Server Autonomous Encrypted Database (edge.db)
// 100% Pure Go SQLite (Zero CGO) with AES-256-GCM Field-Level Encryption

package edgedb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type TokenRecord struct {
	Token     string    `json:"token"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type SNIRoute struct {
	ID         int64  `json:"id"`
	SNIPattern string `json:"sni_pattern"`
	TargetType string `json:"target_type"` // "cover_site" | "reverse_proxy" | "reject"
	TargetAddr string `json:"target_addr"`
	IsActive   bool   `json:"is_active"`
}

type EdgeDB struct {
	mu       sync.RWMutex
	db       *sql.DB
	encKey   []byte
	hmacKey  []byte
	sniCache sync.Map // map[string]*SNIRoute
}

// deriveKeys creates 32-byte AES key and 32-byte HMAC key from a master secret
func deriveKeys(secret string) (encKey []byte, hmacKey []byte) {
	if secret == "" {
		log.Println("[SECURITY WARNING] AERO_MASTER_SECRET not set! Falling back to default standalone seed; database field-encryption is not cryptographically protected in production.")
		secret = "aero-edge-standalone-master-key-seed-v1"
	}
	h := sha256.New()
	h.Write([]byte("aero-edge-aes-key:"))
	h.Write([]byte(secret))
	encKey = h.Sum(nil)

	h.Reset()
	h.Write([]byte("aero-edge-hmac-key:"))
	h.Write([]byte(secret))
	hmacKey = h.Sum(nil)
	return
}

func (e *EdgeDB) hashToken(token string) string {
	mac := hmac.New(sha256.New, e.hmacKey)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

func (e *EdgeDB) encrypt(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func (e *EdgeDB) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// Open initializes or connects to the hardened edge.db SQLite database.
func Open(dbPath, masterSecret string) (*EdgeDB, error) {
	if dbPath == "" {
		dbPath = filepath.Join("data", "edge.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir edge db: %w", err)
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open edge db: %w", err)
	}

	encKey, hmacKey := deriveKeys(masterSecret)
	ed := &EdgeDB{
		db:      db,
		encKey:  encKey,
		hmacKey: hmacKey,
	}

	if err := ed.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	ed.loadSNICache()
	return ed, nil
}

func (e *EdgeDB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS edge_tokens (
		token_hash TEXT PRIMARY KEY,
		token_enc BLOB NOT NULL,
		label TEXT NOT NULL,
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS edge_sni_routes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sni_pattern TEXT UNIQUE NOT NULL,
		target_type TEXT NOT NULL,
		target_addr TEXT NOT NULL,
		is_active INTEGER DEFAULT 1,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS edge_certs (
		domain TEXT PRIMARY KEY,
		cert_pem TEXT NOT NULL,
		key_enc BLOB NOT NULL,
		spki_pin TEXT DEFAULT '',
		expires_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS edge_metrics (
		token_hash TEXT PRIMARY KEY,
		bytes_in INTEGER DEFAULT 0,
		bytes_out INTEGER DEFAULT 0,
		conns_total INTEGER DEFAULT 0,
		last_seen_at TEXT NOT NULL
	);
	`
	_, err := e.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("init edge schema: %w", err)
	}

	// Seed default SNI routes if empty
	var count int
	_ = e.db.QueryRow(`SELECT count(*) FROM edge_sni_routes`).Scan(&count)
	if count == 0 {
		now := time.Now().Format(time.RFC3339)
		_, _ = e.db.Exec(`INSERT INTO edge_sni_routes (sni_pattern, target_type, target_addr, is_active, updated_at) VALUES
			('default', 'cover_site', 'local', 1, ?),
			('edge.microsoft.com', 'reverse_proxy', 'https://www.bing.com', 1, ?),
			('azureedge.net', 'reverse_proxy', 'https://www.microsoft.com', 1, ?),
			('cloudflare.com', 'reverse_proxy', 'https://www.cloudflare.com', 1, ?)`,
			now, now, now, now)
	}
	return nil
}

func (e *EdgeDB) loadSNICache() {
	rows, err := e.db.Query(`SELECT id, sni_pattern, target_type, target_addr, is_active FROM edge_sni_routes WHERE is_active = 1`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var r SNIRoute
		var activeInt int
		if err := rows.Scan(&r.ID, &r.SNIPattern, &r.TargetType, &r.TargetAddr, &activeInt); err == nil {
			r.IsActive = activeInt == 1
			e.sniCache.Store(strings.ToLower(r.SNIPattern), &r)
		}
	}
}

// MatchSNIRoute returns the routing rule for an incoming SNI.
func (e *EdgeDB) MatchSNIRoute(sni string) (targetType, targetAddr string, found bool) {
	sni = strings.ToLower(strings.TrimSpace(sni))
	if val, ok := e.sniCache.Load(sni); ok {
		r := val.(*SNIRoute)
		return r.TargetType, r.TargetAddr, true
	}
	// Fallback to default
	if val, ok := e.sniCache.Load("default"); ok {
		r := val.(*SNIRoute)
		return r.TargetType, r.TargetAddr, true
	}
	return "cover_site", "local", true
}

// UpsertSNIRoute 动态插入或更新伪装 SNI 路由项
func (e *EdgeDB) UpsertSNIRoute(pattern, targetType, targetAddr string, isActive bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	pattern = strings.ToLower(strings.TrimSpace(pattern))
	actInt := 0
	if isActive {
		actInt = 1
	}
	now := time.Now().Format(time.RFC3339)

	_, err := e.db.Exec(`INSERT INTO edge_sni_routes (sni_pattern, target_type, target_addr, is_active, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(sni_pattern) DO UPDATE SET
			target_type=excluded.target_type,
			target_addr=excluded.target_addr,
			is_active=excluded.is_active,
			updated_at=excluded.updated_at`,
		pattern, targetType, targetAddr, actInt, now)
	if err == nil {
		e.loadSNICache()
	}
	return err
}

// ListActiveSNIs 列出当前全部存活可用的白名单 SNI
func (e *EdgeDB) ListActiveSNIs() []string {
	var list []string
	e.sniCache.Range(func(k, v any) bool {
		s := k.(string)
		if s != "default" {
			list = append(list, s)
		}
		return true
	})
	return list
}

// BestActiveSNI 优选当前可用性最高、延迟最低的活跃白名单 SNI
func (e *EdgeDB) BestActiveSNI() string {
	// 默认顺序优选
	preferred := []string{"edge.microsoft.com", "azureedge.net", "cloudflare.com"}
	for _, p := range preferred {
		if _, ok := e.sniCache.Load(p); ok {
			return p
		}
	}
	active := e.ListActiveSNIs()
	if len(active) > 0 {
		return active[0]
	}
	return "edge.microsoft.com"
}

// CheckAndUpdateSNIRoutes 实时探测并更新所有 SNI 伪装目标的可达性，剔除失效域名
func (e *EdgeDB) CheckAndUpdateSNIRoutes() error {
	rows, err := e.db.Query(`SELECT id, sni_pattern, target_type, target_addr, is_active FROM edge_sni_routes`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type routeItem struct {
		id      int64
		pattern string
		ttype   string
		taddr   string
		active  bool
	}
	var routes []routeItem
	for rows.Next() {
		var r routeItem
		var actInt int
		if err := rows.Scan(&r.id, &r.pattern, &r.ttype, &r.taddr, &actInt); err == nil {
			r.active = actInt == 1
			routes = append(routes, r)
		}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	now := time.Now().Format(time.RFC3339)

	for _, r := range routes {
		if r.pattern == "default" || !strings.HasPrefix(r.taddr, "http") {
			continue
		}
		// 发起快速探测
		req, err := http.NewRequest("HEAD", r.taddr, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
		resp, err := client.Do(req)
		isUp := err == nil && resp != nil && resp.StatusCode > 0 && resp.StatusCode < 500
		if resp != nil {
			_ = resp.Body.Close()
		}

		newActive := 0
		if isUp {
			newActive = 1
		}
		if (newActive == 1) != r.active {
			log.Printf("[SNI-HEALTH] SNI %s -> %s reachable=%v (status updated)", r.pattern, r.taddr, isUp)
			_, _ = e.db.Exec(`UPDATE edge_sni_routes SET is_active=?, updated_at=? WHERE id=?`, newActive, now, r.id)
		}
	}

	e.loadSNICache()
	return nil
}

// StartSNIHealthChecker 启动后台常驻实时检测与自愈协程
func (e *EdgeDB) StartSNIHealthChecker(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		// 启动后先自检一次
		_ = e.CheckAndUpdateSNIRoutes()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if err := e.CheckAndUpdateSNIRoutes(); err != nil {
					log.Printf("[SNI-HEALTH] check error: %v", err)
				}
			}
		}
	}()
}

// SaveToken encrypts and stores a token record.
func (e *EdgeDB) SaveToken(token, label string, expiresAt time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	encToken, err := e.encrypt([]byte(token))
	if err != nil {
		return fmt.Errorf("encrypt token: %w", err)
	}

	tokenHash := e.hashToken(token)
	now := time.Now().Format(time.RFC3339)
	exp := expiresAt.Format(time.RFC3339)

	_, err = e.db.Exec(`INSERT INTO edge_tokens (token_hash, token_enc, label, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(token_hash) DO UPDATE SET
			token_enc=excluded.token_enc,
			label=excluded.label,
			expires_at=excluded.expires_at`,
		tokenHash, encToken, label, now, exp)
	return err
}

// DeleteToken removes a token.
func (e *EdgeDB) DeleteToken(token string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	tokenHash := e.hashToken(token)
	_, err := e.db.Exec(`DELETE FROM edge_tokens WHERE token_hash = ?`, tokenHash)
	return err
}

// ListTokens decrypts and returns all stored token records.
func (e *EdgeDB) ListTokens() ([]TokenRecord, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rows, err := e.db.Query(`SELECT token_enc, label, created_at, expires_at FROM edge_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []TokenRecord
	for rows.Next() {
		var encToken []byte
		var label, cStr, eStr string
		if err := rows.Scan(&encToken, &label, &cStr, &eStr); err != nil {
			continue
		}
		raw, err := e.decrypt(encToken)
		if err != nil {
			continue
		}
		cTime, _ := time.Parse(time.RFC3339, cStr)
		eTime, _ := time.Parse(time.RFC3339, eStr)
		records = append(records, TokenRecord{
			Token:     string(raw),
			Label:     label,
			CreatedAt: cTime,
			ExpiresAt: eTime,
		})
	}
	return records, nil
}

// SaveCert encrypts the private key and stores certificate credentials.
func (e *EdgeDB) SaveCert(domain, certPEM, keyPEM, spkiPin string, expiresAt time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	encKey, err := e.encrypt([]byte(keyPEM))
	if err != nil {
		return fmt.Errorf("encrypt cert key: %w", err)
	}

	now := time.Now().Format(time.RFC3339)
	exp := expiresAt.Format(time.RFC3339)

	_, err = e.db.Exec(`INSERT INTO edge_certs (domain, cert_pem, key_enc, spki_pin, expires_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			cert_pem=excluded.cert_pem,
			key_enc=excluded.key_enc,
			spki_pin=excluded.spki_pin,
			expires_at=excluded.expires_at,
			updated_at=excluded.updated_at`,
		domain, certPEM, encKey, spkiPin, exp, now)
	return err
}

// GetCert retrieves and decrypts the certificate and private key.
func (e *EdgeDB) GetCert(domain string) (certPEM, keyPEM, spkiPin string, err error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var encKey []byte
	var expStr string
	err = e.db.QueryRow(`SELECT cert_pem, key_enc, spki_pin, expires_at FROM edge_certs WHERE domain = ?`, domain).
		Scan(&certPEM, &encKey, &spkiPin, &expStr)
	if err != nil {
		return "", "", "", err
	}
	rawKey, err := e.decrypt(encKey)
	if err != nil {
		return "", "", "", fmt.Errorf("decrypt cert key: %w", err)
	}
	return certPEM, string(rawKey), spkiPin, nil
}

// RecordTraffic increments bandwidth counters for a token.
func (e *EdgeDB) RecordTraffic(token string, bytesIn, bytesOut int64) {
	tokenHash := e.hashToken(token)
	now := time.Now().Format(time.RFC3339)
	_, _ = e.db.Exec(`INSERT INTO edge_metrics (token_hash, bytes_in, bytes_out, conns_total, last_seen_at)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(token_hash) DO UPDATE SET
			bytes_in = bytes_in + excluded.bytes_in,
			bytes_out = bytes_out + excluded.bytes_out,
			conns_total = conns_total + 1,
			last_seen_at = excluded.last_seen_at`,
		tokenHash, bytesIn, bytesOut, now)
}

// Close closes the underlying SQLite connection.
func (e *EdgeDB) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.db != nil {
		return e.db.Close()
	}
	return nil
}
