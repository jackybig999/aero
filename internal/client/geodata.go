// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 国内直连规则（域名 + 网段）由服务端节点提供，客户端下载后在本地匹配，不依赖第三方源：
//   - 来源：订阅里的节点（edge）的 GET /api/v1/geodata/direct，带 ETag，304 表示已是最新；
//   - 本地：落盘到数据目录 geodata_direct.txt；启动时先加载上次的副本，再后台刷新；
//   - 生效：先校验与构建索引，成功后先落盘再替换，失败不动现有规则。
const (
	geoDataFileName = "geodata_direct.txt"
	geoDataETagName = "geodata_direct.etag"
	geoDataAPIPath  = "/api/v1/geodata/direct"

	// 规则文件约 1.5 MB（gzip 后约 0.5 MB），慢链路上 30 秒读不完，放宽到 2 分钟
	geoPerTryLimit = 2 * time.Minute
	geoMaxSources  = 5 // 一次同步最多尝试的节点数
)

// 同步节奏。声明为变量只是为了让测试缩短等待；生产不修改。
var (
	geoSyncInterval = 24 * time.Hour // 成功后的刷新间隔
	geoFirstDelay   = 3 * time.Second
	geoRetryMin     = time.Minute
	geoRetryMax     = 2 * time.Hour
	geoNoSourceWait = 10 * time.Second // 订阅尚未载入时的轮询间隔
)

var (
	errNoGeoSource = errors.New("no geodata source: subscription has no node yet")
	errGeoBusy     = errors.New("geodata sync already in progress")
)

// geoSource 是一个可下载规则的地址。
type geoSource struct {
	url        string
	serverName string // TLS ServerName；空表示沿用 URL 主机
	nodeHost   string // 节点真实域名（证书校验的备用名）
	dialAddr   string // 非空时固定拨号到该 host:port（节点 IP），否则按 URL 主机解析
}

// splitHostPortDefault 拆出 host 与端口，缺端口时默认 443。
func splitHostPortDefault(addr string) (string, string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return strings.Trim(addr, "[]"), "443"
}

// geoURLHost 拼 URL 里的 host[:port]：默认端口 443 省略（这样节点来源与订阅主机来源指向同一主机时能去重），
// IPv6 字面量加方括号。
func geoURLHost(host, port string) string {
	if port == "" || port == "443" {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

// geoSources 返回按优先级排列的下载来源：
//  1. 显式设置的 URL（测试与自定义）——只用它；
//  2. 订阅中的节点，当前节点优先，最多 geoMaxSources 个；
//  3. 订阅链接所在主机（兼容旧部署，中台若提供同名接口）。
func (e *Engine) geoSources() []geoSource {
	e.mu.RLock()
	explicit := e.geoDataURL
	applied := e.appliedSub
	subURL := e.savedSubURL
	active := e.activeAddr
	e.mu.RUnlock()

	if explicit != "" {
		return []geoSource{{url: explicit}}
	}

	var out []geoSource
	seen := make(map[string]bool)
	add := func(s geoSource) {
		if len(out) < geoMaxSources && !seen[s.url] {
			seen[s.url] = true
			out = append(out, s)
		}
	}

	if applied != nil {
		servers := append([]ServerConfig(nil), applied.Servers...)
		sort.SliceStable(servers, func(i, j int) bool {
			return servers[i].Address == active && servers[j].Address != active
		})
		for _, s := range servers {
			host, port := splitHostPortDefault(s.Address)
			if s.Host != "" {
				host = s.Host
			}
			if host == "" {
				continue
			}
			src := geoSource{
				url:        "https://" + geoURLHost(host, port) + geoDataAPIPath,
				serverName: s.SNI,
				nodeHost:   host,
			}
			if src.serverName == "" {
				src.serverName = host
			}
			if s.IP != "" {
				src.dialAddr = net.JoinHostPort(s.IP, port)
			}
			add(src)
		}
	}

	if subURL != "" {
		if u, err := url.Parse(subURL); err == nil && u.Hostname() != "" {
			host := u.Hostname()
			port := u.Port()
			if port == "" || port == "443" || port == "80" {
				if cached, ok := GetCachedSubPort(host); ok && cached > 0 {
					port = strconv.Itoa(cached)
				}
			}
			if port == "" || port == "80" {
				port = "443"
			}
			add(geoSource{url: "https://" + geoURLHost(host, port) + geoDataAPIPath})
		}
	}
	return out
}

// geoDataDir 返回规则文件所在目录。
func geoDataDir() string { return GetDataDir() }

// geoCurrentETag 返回用于条件请求的 ETag。只有“内存里已有下发规则且磁盘副本存在”时才发送，
// 否则会因 304 而得不到规则。
func (e *Engine) geoCurrentETag() string {
	if e.splitEngine == nil || !e.splitEngine.HasDirectRules() {
		return ""
	}
	dir := geoDataDir()
	if b, err := os.ReadFile(filepath.Join(dir, geoDataETagName)); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			if _, serr := os.Stat(filepath.Join(dir, geoDataFileName)); serr == nil {
				return t
			}
		}
	}
	if existing, err := os.ReadFile(filepath.Join(dir, geoDataFileName)); err == nil && len(existing) > 0 {
		sum := sha256.Sum256(existing)
		return `"` + hex.EncodeToString(sum[:]) + `"`
	}
	return ""
}

func (e *Engine) setGeoStatus(updated time.Time, errMsg string) {
	e.geoStatMu.Lock()
	defer e.geoStatMu.Unlock()
	if !updated.IsZero() {
		e.geoUpdated = updated
	}
	e.geoLastErr = errMsg
}

func (e *Engine) geoStatus() (int64, string) {
	e.geoStatMu.Lock()
	defer e.geoStatMu.Unlock()
	var ts int64
	if !e.geoUpdated.IsZero() {
		ts = e.geoUpdated.Unix()
	}
	return ts, e.geoLastErr
}

// LoadGeoDataFromDisk 读取上次下载并落盘的规则并生效。文件不存在不是错误（仅用内置规则）。
func (e *Engine) LoadGeoDataFromDisk() (int, error) {
	if e.splitEngine == nil {
		return 0, errors.New("split engine not initialized")
	}
	path := filepath.Join(geoDataDir(), geoDataFileName)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("open geodata: %w", err)
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, geoDataMaxBytes+1))
	if err != nil {
		return 0, fmt.Errorf("read geodata: %w", err)
	}
	if len(body) > geoDataMaxBytes {
		return 0, fmt.Errorf("geodata file exceeds %d bytes limit", geoDataMaxBytes)
	}
	idx := buildDirectIndex(body)
	if idx.count == 0 {
		if idx.rejected != "" {
			return 0, fmt.Errorf("geodata file rejected: %s", idx.rejected)
		}
		return 0, errors.New("geodata file has no valid rules")
	}
	e.splitEngine.installDirect(idx)
	if fi, err := f.Stat(); err == nil {
		e.setGeoStatus(fi.ModTime(), "")
	}
	e.refreshTunRoutes() // 直连网段变了：TUN 路由要同步，否则新直连地址仍被路由进 TUN
	return idx.count, nil
}

// fetchGeoSource 向一个来源发条件请求。返回 (body, etag, notModified, err)。
func (e *Engine) fetchGeoSource(ctx context.Context, src geoSource, currentETag string) ([]byte, string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.url, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "AeroClient/2.0")
	if currentETag != "" {
		req.Header.Set("If-None-Match", currentETag)
	}

	// 必须经 DialPhysicalDirect 走物理网卡，防止 TUN 路由环路；节点地址已在路由规划的 Bypass 中。
	var tlsCfg *tls.Config
	if src.serverName != "" {
		tlsCfg = defaultTLSConfig(src.serverName, src.nodeHost) // 与数据面一致的严格证书校验与钉扎
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			if src.dialAddr != "" {
				addr = src.dialAddr
			}
			return DialPhysicalDirect(c, network, addr)
		},
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   geoPerTryLimit,
		// 不跟随重定向：规则来源固定，避免被带到别处
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("network: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, "", true, nil
	case http.StatusOK:
	default:
		return nil, "", false, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	// 伪装站或错误页会以 200 返回 HTML：拒绝，不能当规则
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); strings.Contains(ct, "text/html") {
		return nil, "", false, errors.New("response is HTML, not a rule list")
	}

	// 限制响应体上限，超限直接报错，不落盘也不替换现有规则
	body, err := io.ReadAll(io.LimitReader(resp.Body, geoDataMaxBytes+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("read body: %w", err)
	}
	if len(body) > geoDataMaxBytes {
		return nil, "", false, fmt.Errorf("body exceeds %d bytes limit", geoDataMaxBytes)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		sum := sha256.Sum256(body)
		etag = `"` + hex.EncodeToString(sum[:]) + `"`
	}
	return body, etag, false, nil
}

// writeGeoFileAtomic 在同目录写临时文件再改名，避免半写入的规则文件。
func writeGeoFileAtomic(dir, name string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return err
	}
	ok = true
	return nil
}

// SyncGeoData 从服务端节点同步最新直连规则。返回 (下发规则条数, 是否有更新, 错误)；引擎内规则总数见状态里的 geo_rule_count。
// 依次尝试各来源，第一个成功即止；全部失败时现有规则保持不变。
func (e *Engine) SyncGeoData(ctx context.Context) (int, bool, error) {
	// 同步互斥：已有同步在进行（后台自动同步最长数分钟）就直接返回，
	// 不排队等锁，也不改动状态（否则等到锁时 ctx 早已过期，会把刚成功的状态写成超时错误）。
	e.geoSyncOnce.Do(func() { e.geoSyncSem = make(chan struct{}, 1) })
	select {
	case e.geoSyncSem <- struct{}{}:
		defer func() { <-e.geoSyncSem }()
	default:
		return 0, false, errGeoBusy
	}

	if e.splitEngine == nil {
		return 0, false, errors.New("split engine not initialized")
	}
	srcs := e.geoSources()
	if len(srcs) == 0 {
		e.setGeoStatus(time.Time{}, errNoGeoSource.Error())
		return 0, false, errNoGeoSource
	}

	currentETag := e.geoCurrentETag()
	var failures []string
	for _, src := range srcs {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err().Error())
			break
		}
		body, etag, notModified, err := e.fetchGeoSource(ctx, src, currentETag)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", src.url, err))
			continue
		}
		if notModified {
			e.setGeoStatus(time.Now(), "")
			return e.splitEngine.DirectRuleCount(), false, nil
		}

		// 先校验：解析后没有任何有效规则就拒绝，绝不用空数据冲掉现有规则
		idx := buildDirectIndex(body)
		if idx.count == 0 {
			reason := "no valid rules in response"
			if idx.rejected != "" {
				reason = "response rejected: " + idx.rejected
			}
			failures = append(failures, fmt.Sprintf("%s: %s", src.url, reason))
			continue
		}
		// 再落盘，成功后才替换内存中的规则
		dir := geoDataDir()
		if err := writeGeoFileAtomic(dir, geoDataFileName, body, 0o644); err != nil {
			e.setGeoStatus(time.Time{}, "write geodata: "+err.Error())
			return 0, false, fmt.Errorf("write geodata: %w", err)
		}
		if err := writeGeoFileAtomic(dir, geoDataETagName, []byte(etag), 0o644); err != nil {
			log.Printf("[GEODATA] write etag failed (next sync will refetch): %v", err)
		}
		e.splitEngine.installDirect(idx)
		e.setGeoStatus(time.Now(), "")
		log.Printf("[GEODATA] updated: %d rules from %s", idx.count, src.url)
		// 直连网段变了：TUN 路由要同步。此前只换了名单，路由还是按旧名单规划的，新增的直连网段仍被路由进 TUN，
		// 数据泵又把“直连”目标的包丢掉，这一批站点成了黑洞，直到重连（连接后约 3 秒的自动同步每次都会触发）。
		// 放在设置状态之后：路由刷新要几百毫秒，不能拖住“同步成功”的状态。
		e.refreshTunRoutes()
		return idx.count, true, nil
	}

	msg := strings.Join(failures, "; ")
	e.setGeoStatus(time.Time{}, msg)
	return 0, false, fmt.Errorf("geodata sync failed: %s", msg)
}

// geoNextDelay 计算下一次同步前的等待：从未成功则很快开始，否则到“上次成功 + 24h”。
func (e *Engine) geoNextDelay() time.Duration {
	e.geoStatMu.Lock()
	last := e.geoUpdated
	e.geoStatMu.Unlock()
	if last.IsZero() {
		return geoFirstDelay
	}
	if d := time.Until(last.Add(geoSyncInterval)); d > geoFirstDelay {
		return d
	}
	return geoFirstDelay
}

// StartGeoDataAutoSync 加载上次落盘的规则并启动后台同步：首次尽快（需订阅里已有节点），之后每 24h；
// 失败按 1 分钟起指数退避到 2 小时。协程随 Engine.Close 退出；重复调用无效。
func (e *Engine) StartGeoDataAutoSync() {
	e.geoAutoOnce.Do(func() {
		// 应急开关：设置 AERO_DISABLE_GEODATA=1 则不加载、不下载服务端下发的直连规则，只用内置规则。
		// 用于排查网络问题时隔离这一功能。
		if os.Getenv("AERO_DISABLE_GEODATA") == "1" {
			log.Printf("[GEODATA] disabled by AERO_DISABLE_GEODATA=1; using built-in rules only")
			return
		}
		if n, err := e.LoadGeoDataFromDisk(); err != nil {
			log.Printf("[GEODATA] load local copy failed: %v", err)
		} else if n > 0 {
			log.Printf("[GEODATA] loaded local copy: %d rules", n)
		}

		ctx := e.daemonCtx
		if ctx == nil {
			return
		}
		done := make(chan struct{})
		e.geoLoopDone = done
		go func() {
			defer close(done)
			next := e.geoNextDelay()
			backoff := geoRetryMin
			for {
				t := time.NewTimer(next)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
				if len(e.geoSources()) == 0 { // 订阅还没载入：稍后再看
					next = geoNoSourceWait
					continue
				}
				sctx, cancel := context.WithTimeout(ctx, geoPerTryLimit*geoMaxSources)
				_, _, err := e.SyncGeoData(sctx)
				cancel()
				if errors.Is(err, errGeoBusy) { // 界面刚好在同步：稍后再来，不计入失败退避
					next = geoRetryMin
					continue
				}
				if err != nil {
					log.Printf("[GEODATA] sync failed (retry in %v): %v", backoff, err)
					next = backoff
					if backoff *= 4; backoff > geoRetryMax {
						backoff = geoRetryMax
					}
					continue
				}
				backoff = geoRetryMin
				next = geoSyncInterval
			}
		}()
	})
}
