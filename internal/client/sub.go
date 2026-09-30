// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// ErrTier1AIExhausted Tier 1 纯净节点熔断保护错误
	ErrTier1AIExhausted = errors.New("TIER1_AI_NODES_EXHAUSTED: 全部 Tier 1 AI 纯净节点满载或下线")
)

// ServerConfig 订阅中的单节点配置契约
type ServerConfig struct {
	Name        string   `json:"name" yaml:"name"`
	Address     string   `json:"address" yaml:"addr"`
	Token       string   `json:"token" yaml:"token"`
	SNI         string   `json:"sni" yaml:"sni"`
	Protocol    string   `json:"protocol" yaml:"protocol"`
	PinSPKI     []string `json:"pin_spki,omitempty" yaml:"pin_spki"`
	PurityScore int      `json:"purityScore,omitempty"`
	AIBlocked   bool     `json:"aiBlocked,omitempty"`
}

// Optimization 调度优化参数
type Optimization struct {
	AINodes    []string `json:"aiNodes,omitempty" yaml:"ai_nodes"`
	GameNodes  []string `json:"gameNodes,omitempty" yaml:"game_nodes"`
	DefaultQoS string   `json:"defaultQoS,omitempty" yaml:"default_qos"`
	Bandwidth  string   `json:"bandwidth,omitempty" yaml:"bandwidth_limit"`
}

// Subscription 瘦客户端专属订阅结构 (aero/2.0)
type Subscription struct {
	Version          string         `json:"version" yaml:"ver"`
	UserID           string         `json:"userId,omitempty" yaml:"user_id"`
	Slug             string         `json:"slug,omitempty" yaml:"slug"`
	SubTicketSeed    string         `json:"subTicketSeed,omitempty" yaml:"sub_ticket_seed"`
	ProtocolPriority []string       `json:"protocolPriority,omitempty" yaml:"protocol_priority"`
	ExpireAt         int64          `json:"expireAt,omitempty" yaml:"expire_at"`
	SwitchStatus     string         `json:"switchStatus,omitempty" yaml:"switch_status"`
	Signature        string         `json:"signature,omitempty" yaml:"sig"`
	Servers          []ServerConfig `json:"servers" yaml:"nodes"`
	CreatedAt        int64          `json:"createdAt,omitempty" yaml:"created_at"`
	Opt              Optimization   `json:"optimization,omitempty" yaml:"optimization"`
}

// IsExpired 检查订阅是否过期或已被管理员关闭
func (s *Subscription) IsExpired() bool {
	if s.SwitchStatus == "off" {
		return true
	}
	if s.ExpireAt <= 0 {
		return false
	}
	return time.Now().Unix() > s.ExpireAt
}

// ToBase64 序列化为 base64
func (s *Subscription) ToBase64() (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(data), nil
}

// Applied 应用到客户端运行时的扁平结果
type Applied struct {
	EdgeAddresses string
	PrimaryToken  string
	PrimarySNI    string
	PrimaryPins   []string
	AllPins       []string
	Tokens        map[string]string
	SNIs          map[string]string
	Servers       []ServerConfig
}

// ApplySubscription 将订阅转为拨号参数
func ApplySubscription(s *Subscription) (*Applied, error) {
	if s == nil || len(s.Servers) == 0 {
		return nil, fmt.Errorf("empty subscription")
	}
	if s.IsExpired() {
		return nil, fmt.Errorf("subscription expired")
	}
	out := &Applied{
		Tokens: make(map[string]string),
		SNIs:   make(map[string]string),
	}
	var addrs []string
	var validServers []ServerConfig
	seenPins := make(map[string]bool)
	var allPins []string
	for _, srv := range s.Servers {
		addr := strings.TrimSpace(srv.Address)
		if addr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err == nil && net.ParseIP(host) == nil && host != "" {
			// 物理 SNI 始终等于节点域名
			srv.SNI = host
		}
		validServers = append(validServers, srv)
		addrs = append(addrs, addr)
		out.Tokens[addr] = srv.Token
		if srv.SNI != "" {
			out.SNIs[addr] = srv.SNI
		}
		for _, p := range srv.PinSPKI {
			p = strings.TrimSpace(p)
			if p != "" && !seenPins[p] {
				seenPins[p] = true
				allPins = append(allPins, p)
			}
		}
	}
	if len(validServers) == 0 {
		return nil, fmt.Errorf("no valid server addresses")
	}
	out.EdgeAddresses = strings.Join(addrs, ",")
	out.PrimaryToken = validServers[0].Token
	out.PrimarySNI = validServers[0].SNI
	out.PrimaryPins = append([]string(nil), validServers[0].PinSPKI...)
	out.AllPins = allPins
	out.Servers = validServers
	return out, nil
}

// SubFetchOptions 订阅拉取参数
type SubFetchOptions struct {
	Purpose      string
	AllowDegrade bool
	ISPHint      string
	Timeout      time.Duration
	DisableCache bool
}

// FetchSubscription 从远端中台或备用源拉取并解析订阅
func FetchSubscription(ctx context.Context, rawURL string, opt SubFetchOptions) (*Subscription, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("empty subscription URL")
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("invalid subscription URL scheme: %s (must be http:// or https://)", rawURL)
	}

	sub, body, err := fetchSingleSubURL(ctx, rawURL, opt)
	if err == nil && sub != nil {
		SaveLastBody(body)
		return sub, nil
	}

	// 关键判定：403 (订阅到期/停用) 或 404 立即清理本地缓存，严禁降级回退旧节点
	if err != nil && (strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "HTTP 404")) {
		ClearLastBody()
		return nil, fmt.Errorf("subscription revoked or expired: %w", err)
	}

	// 端口自适应智能轮试：若标准 HTTPS (443) 获取失败或被第三方霸占 (非 200/连接断开)，
	// 客户端在后台对标准候选 HTTPS 端口进行静默轮试探测，保持外部订阅 URL 绝对纯净
	u, parseErr := url.Parse(rawURL)
	if parseErr == nil && u.Port() == "" && strings.HasPrefix(u.Path, "/sub/") {
		candidatePorts := []string{"8443", "2053", "2083", "2087", "2096"}
		for _, cp := range candidatePorts {
			altU := *u
			altU.Host = net.JoinHostPort(u.Hostname(), cp)
			if altSub, altBody, altErr := fetchSingleSubURL(ctx, altU.String(), opt); altErr == nil && altSub != nil {
				SaveLastBody(altBody)
				return altSub, nil
			}
		}
	}

	// 主 URL 失败时，尝试故障漂移
	if parseErr == nil && u.Path != "" && strings.HasPrefix(u.Path, "/sub/") {
		if cached := LoadLastBody(); len(cached) > 0 {
			if lastSub, perr := ParseSubscriptionBytes(cached); perr == nil && len(lastSub.Servers) > 0 {
				scheme := u.Scheme
				if scheme == "" {
					scheme = "https"
				}
				for _, srv := range lastSub.Servers {
					altAddr := srv.Address
					if altAddr == "" || altAddr == u.Host {
						continue
					}
					altURL := fmt.Sprintf("%s://%s%s", scheme, altAddr, u.Path)
					if altSub, altBody, altErr := fetchSingleSubURL(ctx, altURL, opt); altErr == nil && altSub != nil {
						SaveLastBody(altBody)
						return altSub, nil
					}
				}
			}
		}
	}

	if !opt.DisableCache {
		if cached := LoadLastBody(); len(cached) > 0 {
			if sub, perr := ParseSubscriptionBytes(cached); perr == nil {
				return sub, nil
			}
		}
	}
	return nil, fmt.Errorf("fetch subscription (all sources failed): %w", err)
}

func fetchSingleSubURL(ctx context.Context, targetURL string, opt SubFetchOptions) (*Subscription, []byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, err
	}

	q := u.Query()
	if opt.Purpose != "" {
		q.Set("purpose", opt.Purpose)
	}
	if opt.AllowDegrade {
		q.Set("allow_degrade", "true")
	}
	if opt.ISPHint != "" {
		q.Set("isp", opt.ISPHint)
	}
	u.RawQuery = q.Encode()

	timeout := 15 * time.Second
	if opt.Timeout > 0 {
		timeout = opt.Timeout
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "AeroClient/2.0")

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			return DialPhysicalDirect(c, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch subscription network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error == "TIER1_AI_NODES_EXHAUSTED" {
			return nil, nil, ErrTier1AIExhausted
		}
		return nil, nil, fmt.Errorf("subscription service unavailable (503): %s", errBody.Error)
	}

	if resp.StatusCode == http.StatusForbidden {
		return nil, nil, fmt.Errorf("HTTP 403 Forbidden")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, fmt.Errorf("HTTP 404 Not Found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("subscription HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read subscription body failed: %w", err)
	}

	sub, err := ParseSubscriptionBytes(body)
	if err != nil {
		return nil, nil, err
	}
	return sub, body, nil
}

// ParseSubscriptionBytes 解析 Base64 或原始 JSON 订阅报文
func ParseSubscriptionBytes(data []byte) (*Subscription, error) {
	dataStr := strings.TrimSpace(string(data))
	if decoded, err := base64.StdEncoding.DecodeString(dataStr); err == nil && len(decoded) > 0 {
		data = decoded
	} else if decoded, err := base64.RawStdEncoding.DecodeString(dataStr); err == nil && len(decoded) > 0 {
		data = decoded
	} else if decoded, err := base64.URLEncoding.DecodeString(dataStr); err == nil && len(decoded) > 0 {
		data = decoded
	} else if decoded, err := base64.RawURLEncoding.DecodeString(dataStr); err == nil && len(decoded) > 0 {
		data = decoded
	}

	var sub Subscription
	if err := json.Unmarshal(data, &sub); err != nil {
		return nil, fmt.Errorf("subscription json unmarshal failed: %w", err)
	}
	return &sub, nil
}

// DeriveNodeToken 基于用户种子和目标域名派生单节点动态访问 Token
func DeriveNodeToken(seed, domain string) string {
	if seed == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(seed + ":" + strings.ToLower(strings.TrimSpace(domain))))
	return "tok_" + hex.EncodeToString(h.Sum(nil))[:24]
}

var lastBodyMu sync.RWMutex

// SaveLastBody 本地保存最后一次成功拉取的有效订阅
func SaveLastBody(body []byte) {
	if len(body) == 0 {
		return
	}
	lastBodyMu.Lock()
	defer lastBodyMu.Unlock()
	p := lastBodyPath()
	if p != "" {
		_ = os.WriteFile(p, body, 0o600)
	}
}

// LoadLastBody 加载本地订阅缓存
func LoadLastBody() []byte {
	lastBodyMu.RLock()
	defer lastBodyMu.RUnlock()
	p := lastBodyPath()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}

// ClearLastBody 清理本地订阅缓存
func ClearLastBody() {
	lastBodyMu.Lock()
	defer lastBodyMu.Unlock()
	p := lastBodyPath()
	if p != "" {
		_ = os.Remove(p)
	}
}

func lastBodyPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), ".last-sub-body")
	}
	if wd, err := os.Getwd(); err == nil {
		return filepath.Join(wd, ".last-sub-body")
	}
	return ""
}
