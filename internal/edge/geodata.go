// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultGeoDataURL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"
const fallbackGeoDataURL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/direct-list.txt"

// 中国网段（每行一个 CIDR，含 IPv6）。与域名列表合并成同一个下发文件，客户端按行区分。
const defaultGeoIPURL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt"
const fallbackGeoIPURL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/cn.txt"

// maxGeoIPLines 限制合并进下发文件的网段行数，防止上游异常数据撑大文件。
const maxGeoIPLines = 50000

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

// countRules counts valid direct rule entries, ignoring empty lines and comments
func countRules(data []byte) int {
	count := 0
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			count++
		}
	}
	return count
}

// GeoDataHandler manages direct rules dataset and handles HTTP /geodata/direct-list requests
type GeoDataHandler struct {
	mu         sync.RWMutex
	data       []byte
	etag       string
	rulesCount int
	lastUpdate time.Time
	dataDir    string
	filePath   string

	cronInterval time.Duration

	fetchURL   string
	httpClient *http.Client

	gzMu    sync.Mutex
	gzEtag  string // 当前压缩副本对应的 ETag
	gzBytes []byte
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
		h.rulesCount = countRules(data)
		if fi, fierr := os.Stat(filePath); fierr == nil {
			h.lastUpdate = fi.ModTime()
		} else {
			h.lastUpdate = time.Now()
		}
		sum := sha256.Sum256(data)
		h.etag = fmt.Sprintf("\"%x\"", sum)
	} else {
		defaultData := []byte(defaultDirectRules)
		h.data = defaultData
		h.rulesCount = countRules(defaultData)
		h.lastUpdate = time.Now()
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
	// Initial update immediately in background to eliminate 24h cold-start wait
	go func() {
		if err := h.fetchAndUpdateWithContext(ctx); err != nil {
			log.Printf("[GEODATA] Initial startup update failed: %v", err)
		}
	}()
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

func (h *GeoDataHandler) fetchAndUpdateWithContext(parentCtx context.Context) error {
	urls := []string{h.fetchURL}
	if h.fetchURL == "" || h.fetchURL == defaultGeoDataURL {
		urls = []string{defaultGeoDataURL, fallbackGeoDataURL}
	}

	client := h.httpClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	var lastErr error
	for _, targetURL := range urls {
		body, err := h.tryFetchURL(parentCtx, client, targetURL)
		if err != nil {
			lastErr = err
			continue
		}
		body = h.withIPRanges(parentCtx, client, body)

		sum := sha256.Sum256(body)
		newEtag := fmt.Sprintf("\"%x\"", sum)

		h.mu.RLock()
		currentEtag := h.etag
		h.mu.RUnlock()

		if newEtag == currentEtag {
			h.mu.Lock()
			h.lastUpdate = time.Now()
			h.mu.Unlock()
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
		h.rulesCount = countRules(body)
		h.lastUpdate = time.Now()
		h.mu.Unlock()

		log.Printf("[GEODATA] Updated geodata direct list (%d rules, %d bytes, etag: %s) from %s", h.rulesCount, len(body), newEtag, targetURL)
		return nil
	}

	return fmt.Errorf("all geodata upstream fetches failed, last error: %w", lastErr)
}

// 网段宽度下限：真实 cn.txt 最宽为 IPv4 /10、IPv6 /19。一行 0.0.0.0/0 会让客户端把全部流量判为直连，
// 所以上游数据里更宽的网段一律丢弃（客户端也会独立校验）。
const (
	minGeoIPv4Prefix = 8
	minGeoIPv6Prefix = 16
)

// isCIDRLine 判断一行是否为可下发的 CIDR：格式合法且不比宽度下限更宽。
func isCIDRLine(line string) bool {
	_, n, err := net.ParseCIDR(line)
	if err != nil {
		return false
	}
	ones, _ := n.Mask.Size()
	if n.IP.To4() != nil {
		return ones >= minGeoIPv4Prefix
	}
	return ones >= minGeoIPv6Prefix
}

// extractCIDRLines 从下发文件中取出全部 CIDR 行（网段失败时沿用上一次的网段）。
func extractCIDRLines(data []byte) []string {
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(l); t != "" && isCIDRLine(t) {
			out = append(out, t)
		}
	}
	return out
}

// withIPRanges 把中国网段合并到域名列表之后。仅在使用默认上游时执行（自定义 fetchURL 的部署/测试不受影响）。
// 网段获取是尽力而为：失败或没有合法行时沿用当前文件里已有的网段，域名更新不受牵连。
func (h *GeoDataHandler) withIPRanges(ctx context.Context, client *http.Client, domains []byte) []byte {
	if h.fetchURL != "" && h.fetchURL != defaultGeoDataURL {
		return domains
	}
	var cidrs []string
	for _, u := range []string{defaultGeoIPURL, fallbackGeoIPURL} {
		raw, err := h.tryFetchURL(ctx, client, u)
		if err != nil {
			log.Printf("[GEODATA] china ip list fetch failed (%s): %v", u, err)
			continue
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if t := strings.TrimSpace(l); t != "" && isCIDRLine(t) {
				cidrs = append(cidrs, t)
				if len(cidrs) >= maxGeoIPLines {
					break
				}
			}
		}
		if len(cidrs) > 0 {
			break
		}
		log.Printf("[GEODATA] china ip list from %s has no valid CIDR lines", u)
	}
	if len(cidrs) == 0 {
		h.mu.RLock()
		cidrs = extractCIDRLines(h.data)
		h.mu.RUnlock()
	}
	if len(cidrs) == 0 {
		return domains
	}
	var b strings.Builder
	b.Grow(len(domains) + len(cidrs)*16 + 32)
	b.Write(domains)
	if !strings.HasSuffix(string(domains), "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("# --- China IP ranges ---\n")
	for _, c := range cidrs {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func (h *GeoDataHandler) tryFetchURL(parentCtx context.Context, client *http.Client, fetchURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parentCtx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create geodata request: %w", err)
	}
	req.Header.Set("User-Agent", "AERO-Edge-GeoData/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch geodata error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch geodata unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB safety cap
	if err != nil {
		return nil, fmt.Errorf("read geodata body: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("fetched geodata is empty")
	}
	return body, nil
}

// TryServe intercepts GET/HEAD /geodata/direct-list and /api/v1/geodata/direct:
// Returns 304 Not Modified if If-None-Match matches etag;
// Otherwise returns 200 OK with ETag header and rules text.
func (h *GeoDataHandler) TryServe(w http.ResponseWriter, r *http.Request) bool {
	if h == nil {
		return false
	}
	path := r.URL.Path
	if path != "/geodata/direct-list" && path != "/geodata/direct-list/" &&
		path != "/api/v1/geodata/direct" && path != "/api/v1/geodata/direct/" {
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

	// 内容随 Accept-Encoding 变化（gzip 能把约 1.5 MB 压到约 0.5 MB，对慢链路影响很大）
	w.Header().Set("Vary", "Accept-Encoding")

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
	if acceptsGzip(r.Header.Get("Accept-Encoding")) {
		if gz := h.gzipped(etag, data); gz != nil {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(len(gz)))
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = w.Write(gz)
			}
			return true
		}
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
	return true
}

// acceptsGzip 判断 Accept-Encoding 是否接受 gzip（含 q=0 表示拒绝的情况）。
func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(fields[0]), "gzip") {
			continue
		}
		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if strings.HasPrefix(f, "q=") {
				if q, err := strconv.ParseFloat(strings.TrimPrefix(f, "q="), 64); err == nil && q <= 0 {
					return false
				}
			}
		}
		return true
	}
	return false
}

// gzipped 返回与 etag 对应的压缩副本（按 etag 缓存，数据更新后重新压缩）。失败返回 nil，调用方回退为明文。
func (h *GeoDataHandler) gzipped(etag string, data []byte) []byte {
	h.gzMu.Lock()
	defer h.gzMu.Unlock()
	if h.gzBytes != nil && h.gzEtag == etag {
		return h.gzBytes
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil
	}
	if _, err := zw.Write(data); err != nil {
		return nil
	}
	if err := zw.Close(); err != nil {
		return nil
	}
	h.gzEtag, h.gzBytes = etag, buf.Bytes()
	return h.gzBytes
}

// GetStatus returns current rule count, last update time, and etag
func (h *GeoDataHandler) GetStatus() (rulesCount int, lastUpdate time.Time, etag string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.rulesCount, h.lastUpdate, h.etag
}

// ForceUpdate triggers an immediate update from upstream
func (h *GeoDataHandler) ForceUpdate(ctx context.Context) error {
	return h.fetchAndUpdateWithContext(ctx)
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
