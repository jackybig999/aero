// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultGeoDataURL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"

const defaultDirectRules = `# China Direct Domain & IP Rules (Built-in Fallback)
cn
114.114.114.114
223.5.5.5
223.6.6.6
119.29.29.29
baidu.com
qq.com
taobao.com
alipay.com
jd.com
163.com
sina.com.cn
sohu.com
bilibili.com
zhihu.com
weibo.com
bytedance.com
douyin.com
toutiao.com
meituan.com
dianping.com
xiaomi.com
huawei.com
tencent.com
aliyun.com
`

// GeoDataHandler manages direct rules dataset and handles HTTP /geodata/direct-list requests
type GeoDataHandler struct {
	mu       sync.RWMutex
	data     []byte
	etag     string
	dataDir  string
	filePath string

	cronInterval time.Duration

	fetchURL   string
	httpClient *http.Client
}

// NewGeoDataHandler initializes a GeoDataHandler from local cache if present, or built-in rules
func NewGeoDataHandler(dataDir string) *GeoDataHandler {
	if dataDir == "" {
		dataDir = "./data"
	}
	absDir, err := filepath.Abs(dataDir)
	if err != nil {
		absDir = dataDir
	}
	filePath := filepath.Join(absDir, "geodata_direct.txt")

	h := &GeoDataHandler{
		dataDir:      absDir,
		filePath:     filePath,
		cronInterval: 24 * time.Hour,
	}

	data, err := os.ReadFile(filePath)
	if err == nil && len(data) > 0 {
		h.data = data
		sum := sha256.Sum256(data)
		h.etag = fmt.Sprintf("\"%x\"", sum)
	} else {
		defaultData := []byte(defaultDirectRules)
		h.data = defaultData
		sum := sha256.Sum256(defaultData)
		h.etag = fmt.Sprintf("\"%x\"", sum)
	}

	return h
}

// StartCronUpdate runs a background goroutine that polls and updates geodata periodically
func (h *GeoDataHandler) StartCronUpdate(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	interval := h.cronInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := h.fetchAndUpdateWithContext(ctx); err != nil {
					log.Printf("[GEODATA] Periodic update failed: %v", err)
				}
			}
		}
	}()
}

// fetchAndUpdate pulls China direct rules from upstream, calculates SHA256,
// atomically writes to filePath (.tmp -> Rename) if changed, and updates memory.
func (h *GeoDataHandler) fetchAndUpdate() error {
	return h.fetchAndUpdateWithContext(context.Background())
}

func (h *GeoDataHandler) fetchAndUpdateWithContext(parentCtx context.Context) error {
	fetchURL := h.fetchURL
	if fetchURL == "" {
		fetchURL = defaultGeoDataURL
	}

	client := h.httpClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	ctx, cancel := context.WithTimeout(parentCtx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return fmt.Errorf("create geodata request: %w", err)
	}
	req.Header.Set("User-Agent", "AERO-Edge-GeoData/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch geodata error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch geodata unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB safety cap
	if err != nil {
		return fmt.Errorf("read geodata body: %w", err)
	}
	if len(body) == 0 {
		return fmt.Errorf("fetched geodata is empty")
	}

	sum := sha256.Sum256(body)
	newEtag := fmt.Sprintf("\"%x\"", sum)

	h.mu.RLock()
	currentEtag := h.etag
	h.mu.RUnlock()

	if newEtag == currentEtag {
		return nil
	}

	// Atomic disk persistence: write to .tmp, then rename
	if err := os.MkdirAll(h.dataDir, 0o755); err != nil {
		return fmt.Errorf("create geodata dir: %w", err)
	}

	tmpFile := h.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, body, 0o644); err != nil {
		return fmt.Errorf("write temp geodata: %w", err)
	}
	if err := os.Rename(tmpFile, h.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("rename geodata: %w", err)
	}

	h.mu.Lock()
	h.data = body
	h.etag = newEtag
	h.mu.Unlock()

	log.Printf("[GEODATA] Updated geodata direct list (%d bytes, etag: %s)", len(body), newEtag)
	return nil
}

// TryServe intercepts GET/HEAD /geodata/direct-list:
// Returns 304 Not Modified if If-None-Match matches etag;
// Otherwise returns 200 OK with ETag header and rules text.
func (h *GeoDataHandler) TryServe(w http.ResponseWriter, r *http.Request) bool {
	if h == nil {
		return false
	}
	path := r.URL.Path
	if path != "/geodata/direct-list" && path != "/geodata/direct-list/" {
		return false
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}

	h.mu.RLock()
	etag := h.etag
	data := h.data
	h.mu.RUnlock()

	clientETag := r.Header.Get("If-None-Match")
	if etag != "" && clientETag != "" {
		if clientETag == etag || strings.Trim(clientETag, `"`) == strings.Trim(etag, `"`) {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}

	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
	return true
}

// Data returns a copy of the current cached rules data
func (h *GeoDataHandler) Data() []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]byte, len(h.data))
	copy(out, h.data)
	return out
}

// ETag returns the current ETag
func (h *GeoDataHandler) ETag() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.etag
}
