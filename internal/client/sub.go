// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"crypto/hmac"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrTier1AIExhausted Tier 1 纯净节点熔断保护错误
	ErrTier1AIExhausted = errors.New("TIER1_AI_NODES_EXHAUSTED: 全部 Tier 1 AI 纯净节点满载或下线")
)

// ServerConfig 订阅中的单节点配置契约
type ServerConfig struct {
	Name        string   `json:"name" yaml:"name"`
	Host        string   `json:"host,omitempty" yaml:"host"`
	Address     string   `json:"address" yaml:"addr"`
	IP          string   `json:"ip,omitempty" yaml:"ip"`
	Token       string   `json:"token" yaml:"token"`
	SNI         string   `json:"sni" yaml:"sni"`
	Protocol    string   `json:"protocol" yaml:"protocol"`
	PinSPKI     []string `json:"pin_spki,omitempty" yaml:"pin_spki"`
	PurityScore int      `json:"purityScore,omitempty"`
	AIBlocked   bool     `json:"aiBlocked,omitempty"`
	LineType    string   `json:"line_type,omitempty" yaml:"line_type"`
	ISPAffinity string   `json:"isp_affinity,omitempty" yaml:"isp_affinity"`
	AltPorts    []int    `json:"alt_ports,omitempty" yaml:"alt_ports"`
	ECH         string   `json:"ech,omitempty" yaml:"ech"`
	ECHConfig   string   `json:"ech_config,omitempty" yaml:"ech_config"`
	Country     string   `json:"country,omitempty" yaml:"country"`
	WarpActive  bool     `json:"warp_active,omitempty" yaml:"warp_active"`
	Tags        []string `json:"tags,omitempty" yaml:"tags"`
}

// UnmarshalJSON 兼容 snake_case 与 camelCase，杜绝跨系统命名失配导致的静默丢弃
func (s *ServerConfig) UnmarshalJSON(data []byte) error {
	type Alias ServerConfig
	aux := struct {
		*Alias
		LegacyISPAffinity string   `json:"ispAffinity"`
		LegacyLineType    string   `json:"lineType"`
		LegacyAltPorts    []int    `json:"altPorts"`
		LegacyECHConfig   string   `json:"echConfig"`
		LegacyServerECH   string   `json:"ech"`
		SnakePurityScore  int      `json:"purity_score"`
		SnakeAIBlocked    bool     `json:"ai_blocked"`
		CamelWarpActive   bool     `json:"warpActive"`
		SnakeWarp         bool     `json:"warp"`
		SnakeIsWARPEgress bool     `json:"is_warp_egress"`
		CamelIsWARPEgress bool     `json:"isWarpEgress"`
		CamelCountryCode  string   `json:"countryCode"`
		SnakeCountryCode  string   `json:"country_code"`
		AltTags           []string `json:"tag"`
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
	if s.ECH == "" && aux.LegacyServerECH != "" {
		s.ECH = aux.LegacyServerECH
	}
	if s.ECH == "" && s.ECHConfig != "" {
		s.ECH = s.ECHConfig
	}
	if s.ECHConfig == "" && s.ECH != "" {
		s.ECHConfig = s.ECH
	}
	if s.PurityScore == 0 && aux.SnakePurityScore != 0 {
		s.PurityScore = aux.SnakePurityScore
	}
	if !s.AIBlocked && aux.SnakeAIBlocked {
		s.AIBlocked = aux.SnakeAIBlocked
	}
	if !s.WarpActive {
		s.WarpActive = aux.CamelWarpActive || aux.SnakeWarp || aux.SnakeIsWARPEgress || aux.CamelIsWARPEgress
	}
	if s.Country == "" {
		if aux.CamelCountryCode != "" {
			s.Country = aux.CamelCountryCode
		} else if aux.SnakeCountryCode != "" {
			s.Country = aux.SnakeCountryCode
		}
	}
	if len(s.Tags) == 0 && len(aux.AltTags) > 0 {
		s.Tags = aux.AltTags
	}
	return nil
}

// sortServersByISP 纯函数：使用 sort.SliceStable 优先将 ISPAffinity == isp 的节点排在前面
func sortServersByISP(servers []ServerConfig, isp string) {
	if len(servers) <= 1 || isp == "" {
		return
	}
	ispUpper := strings.ToUpper(strings.TrimSpace(isp))
	sort.SliceStable(servers, func(i, j int) bool {
		affI := strings.ToUpper(strings.TrimSpace(servers[i].ISPAffinity))
		affJ := strings.ToUpper(strings.TrimSpace(servers[j].ISPAffinity))
		matchI := affI == ispUpper
		matchJ := affJ == ispUpper
		if matchI && !matchJ {
			return true
		}
		return false
	})
}

// Optimization 调度优化参数
type Optimization struct {
	AINodes    []string `json:"aiNodes,omitempty" yaml:"ai_nodes"`
	GameNodes  []string `json:"gameNodes,omitempty" yaml:"game_nodes"`
	DefaultQoS string   `json:"defaultQoS,omitempty" yaml:"default_qos"`
	Bandwidth  string   `json:"bandwidth,omitempty" yaml:"bandwidth_limit"`
}

// Subscription 瘦客户端专属订阅结构 (aero/3.0)
type Subscription struct {
	Version           string         `json:"version" yaml:"ver"`
	UserID            string         `json:"userId,omitempty" yaml:"user_id"`
	Slug              string         `json:"slug,omitempty" yaml:"slug"`
	SubTicketSeed     string         `json:"subTicketSeed,omitempty" yaml:"sub_ticket_seed"`
	ProtocolPriority  []string       `json:"protocolPriority,omitempty" yaml:"protocol_priority"`
	ExpireAt          int64          `json:"expireAt,omitempty" yaml:"expire_at"`
	TrafficLimitBytes int64          `json:"trafficLimitBytes,omitempty" yaml:"traffic_limit_bytes"`
	TrafficUsedBytes  int64          `json:"trafficUsedBytes,omitempty" yaml:"traffic_used_bytes"`
	SwitchStatus      string         `json:"switchStatus,omitempty" yaml:"switch_status"`
	Signature         string         `json:"signature,omitempty" yaml:"sig"`
	Servers           []ServerConfig `json:"servers" yaml:"nodes"`
	CreatedAt         int64          `json:"createdAt,omitempty" yaml:"created_at"`
	Opt               Optimization   `json:"optimization,omitempty" yaml:"optimization"`
}

func (s *Subscription) UnmarshalJSON(data []byte) error {
	type Alias Subscription
	aux := struct {
		*Alias
		SnakeTrafficLimit int64 `json:"traffic_limit_bytes"`
		CamelTrafficLimit int64 `json:"trafficLimitBytes"`
		SnakeTrafficUsed  int64 `json:"traffic_used_bytes"`
		CamelTrafficUsed  int64 `json:"trafficUsedBytes"`
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
	return nil
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

// IsTrafficExceeded 检查用户流量是否超限
func (s *Subscription) IsTrafficExceeded() bool {
	if s.TrafficLimitBytes <= 0 {
		return false
	}
	return s.TrafficUsedBytes >= s.TrafficLimitBytes
}

// ValidateAndNormalize 强校验与主动安全兜底，杜绝遗漏字段与空值
func (s *Subscription) ValidateAndNormalize() error {
	if s == nil || len(s.Servers) == 0 {
		return fmt.Errorf("empty subscription: no servers configured")
	}
	for i := range s.Servers {
		srv := &s.Servers[i]
		if strings.TrimSpace(srv.Address) == "" && strings.TrimSpace(srv.Host) == "" {
			return fmt.Errorf("server[%d] missing address and host", i)
		}
		if strings.TrimSpace(srv.Address) == "" && srv.Host != "" {
			srv.Address = strings.TrimSpace(srv.Host)
			if !strings.Contains(srv.Address, ":") {
				srv.Address = net.JoinHostPort(srv.Address, "443")
			}
		}
		if strings.TrimSpace(srv.Host) == "" && srv.Address != "" {
			if h, _, err := net.SplitHostPort(strings.TrimSpace(srv.Address)); err == nil {
				srv.Host = h
			} else {
				srv.Host = strings.TrimSpace(srv.Address)
			}
		}
		if strings.TrimSpace(srv.Name) == "" {
			srv.Name = srv.Address
		}
		if strings.TrimSpace(srv.Token) == "" {
			return fmt.Errorf("server[%d] (%s) missing token", i, srv.Name)
		}
		// 若服务端未下发备用端口，主动注入高防备用端口池，保障自愈避障能力；同时过滤掉主端口与重复端口
		var mainPort int
		if _, pStr, err := net.SplitHostPort(srv.Address); err == nil {
			mainPort, _ = strconv.Atoi(pStr)
		}
		if mainPort <= 0 {
			mainPort = 443
		}
		if len(srv.AltPorts) == 0 {
			candidates := StandardCandidatePorts
			if mainPort == 443 {
				srv.AltPorts = append([]int(nil), candidates...)
			} else {
				srv.AltPorts = []int{443}
				for _, cp := range candidates {
					if cp != mainPort {
						srv.AltPorts = append(srv.AltPorts, cp)
					}
				}
			}
		} else {
			filtered := make([]int, 0, len(srv.AltPorts))
			seen := make(map[int]bool)
			for _, cp := range srv.AltPorts {
				if cp > 0 && cp != mainPort && !seen[cp] {
					seen[cp] = true
					filtered = append(filtered, cp)
				}
			}
			srv.AltPorts = filtered
		}
		// 若 IP 为空，尝试从 Host 或 Address 中提取有效 IPv4 自动补齐，杜绝空值
		if srv.IP == "" {
			hostCandidate := strings.TrimSpace(srv.Host)
			if hostCandidate == "" && srv.Address != "" {
				if h, _, err := net.SplitHostPort(strings.TrimSpace(srv.Address)); err == nil {
					hostCandidate = h
				} else {
					hostCandidate = strings.TrimSpace(srv.Address)
				}
			}
			if hostCandidate != "" {
				if ip := net.ParseIP(hostCandidate); ip != nil && ip.To4() != nil {
					srv.IP = ip.String()
				}
			}
		}
		// 跨系统 ECH 与 ECHConfig 双向归一化，杜绝跨系统命名失配
		if srv.ECH != "" && srv.ECHConfig == "" {
			srv.ECHConfig = srv.ECH
		} else if srv.ECHConfig != "" && srv.ECH == "" {
			srv.ECH = srv.ECHConfig
		}
	}
	return nil
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
	ECHConfigs    map[string][]byte
	IPs           map[string]string
	AltPorts      map[string][]int
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
		Tokens:     make(map[string]string),
		SNIs:       make(map[string]string),
		ECHConfigs: make(map[string][]byte),
		IPs:        make(map[string]string),
		AltPorts:   make(map[string][]int),
	}
	var addrs []string
	var validServers []ServerConfig
	seenPins := make(map[string]bool)
	var allPins []string
	for _, srv := range s.Servers {
		addr := strings.TrimSpace(srv.Address)
		if addr == "" && srv.Host != "" {
			addr = strings.TrimSpace(srv.Host)
			if !strings.Contains(addr, ":") {
				addr = net.JoinHostPort(addr, "443")
			}
		}
		if addr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err == nil && net.ParseIP(host) == nil && host != "" {
			// 物理 SNI 始终等于节点域名
			srv.SNI = host
		}
		srv.Address = addr
		validServers = append(validServers, srv)
		addrs = append(addrs, addr)
		out.Tokens[addr] = srv.Token
		if srv.SNI != "" {
			out.SNIs[addr] = srv.SNI
		}
		if srv.IP != "" {
			out.IPs[addr] = srv.IP
		}
		if len(srv.AltPorts) > 0 {
			out.AltPorts[addr] = append([]int(nil), srv.AltPorts...)
		}
		if srv.ECH != "" {
			trimmed := strings.TrimSpace(srv.ECH)
			if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
				out.ECHConfigs[addr] = decoded
			} else if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
				out.ECHConfigs[addr] = decoded
			}
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

// subPortCacheMu 保护 subPortCache 内存端口映射表
var (
	subPortCacheMu sync.RWMutex
	subPortCache   = make(map[string]int) // normalized host -> working port
)

// GetCachedSubPort 返回指定主机名已缓存的有效工作端口，若未缓存返回 0, false
func GetCachedSubPort(host string) (int, bool) {
	norm := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(norm); err == nil {
		norm = h
	}
	norm = strings.Trim(norm, "[]")

	subPortCacheMu.RLock()
	defer subPortCacheMu.RUnlock()
	p, ok := subPortCache[norm]
	if !ok || p <= 0 {
		return 0, false
	}
	return p, true
}

// SetCachedSubPort 记录指定主机名工作端口（线程安全）
func SetCachedSubPort(host string, port int) {
	norm := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(norm); err == nil {
		norm = h
	}
	norm = strings.Trim(norm, "[]")

	subPortCacheMu.Lock()
	defer subPortCacheMu.Unlock()
	if port <= 0 {
		delete(subPortCache, norm)
	} else {
		subPortCache[norm] = port
	}
}

// ClearCachedSubPorts 清空全部缓存的订阅工作端口
func ClearCachedSubPorts() {
	subPortCacheMu.Lock()
	defer subPortCacheMu.Unlock()
	subPortCache = make(map[string]int)
}

// FormatZeroPortSubURL 格式化纯净零端口订阅 URL: https://{host}/sub/{slug}
// 严格遵守 Rule 4 零跨系统导入，客户端独立实现契约对齐
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

// RenderNodeBadgesSlice 根据节点属性生成权威徽章切片
func RenderNodeBadgesSlice(country string, purityScore int, aiBlocked bool, warpActive bool) []string {
	var badges []string
	cUpper := strings.ToUpper(strings.TrimSpace(country))
	switch cUpper {
	case "US":
		badges = append(badges, "[🇺🇸 原生]")
	case "HK":
		badges = append(badges, "[🇭🇰 原生]")
	case "JP":
		badges = append(badges, "[🇯🇵 原生]")
	case "SG":
		badges = append(badges, "[🇸🇬 原生]")
	case "TW":
		badges = append(badges, "[🇹🇼 原生]")
	case "KR":
		badges = append(badges, "[🇰🇷 原生]")
	case "UK", "GB":
		badges = append(badges, "[🇬🇧 原生]")
	case "DE":
		badges = append(badges, "[🇩🇪 原生]")
	default:
		if country != "" {
			badges = append(badges, fmt.Sprintf("[%s 原生]", country))
		}
	}

	if !aiBlocked && purityScore >= 80 {
		badges = append(badges, "[✨ Gemini 解锁]")
	}

	if warpActive {
		badges = append(badges, "[🛡️ WARP 接管]")
	}

	return badges
}

// RenderNodeBadges 格式化徽章字符串（以空格分隔）
func RenderNodeBadges(country string, purityScore int, aiBlocked bool, warpActive bool) string {
	return strings.Join(RenderNodeBadgesSlice(country, purityScore, aiBlocked, warpActive), " ")
}

// probeCandidatePortsLadder 实施 RFC 8305 风格阶梯并发竞速探测候选端口池
// 顺位严格对齐 StandardCandidatePorts = []int{2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443}
// 阶梯发射间隔 60ms；首个成功返回有效 AERO 订阅的端口赢得竞速，原子取消其余并发探测，返回胜出结果与端口
func probeCandidatePortsLadder(ctx context.Context, scheme, hostOnly, requestURI string, opt SubFetchOptions) (*Subscription, []byte, int, error) {
	candPorts := StandardCandidatePorts
	if len(candPorts) == 0 {
		return nil, nil, 0, errors.New("no candidate ports configured")
	}

	ladderOverallTimeout := 6000 * time.Millisecond
	if opt.Timeout > 0 && opt.Timeout < ladderOverallTimeout {
		ladderOverallTimeout = opt.Timeout
	}

	ladderCtx, ladderCancel := context.WithTimeout(ctx, ladderOverallTimeout)
	defer ladderCancel()

	raceCtx, raceCancel := context.WithCancel(ladderCtx)
	defer raceCancel()

	type probeResult struct {
		sub  *Subscription
		body []byte
		port int
		err  error
	}

	resCh := make(chan probeResult, len(candPorts))
	var activeProbes atomic.Int32
	var winOnce sync.Once

	launchProbe := func(port int) {
		activeProbes.Add(1)
		go func(p int) {
			defer activeProbes.Add(-1)
			altURL := fmt.Sprintf("%s://%s:%d%s", scheme, hostOnly, p, requestURI)
			portTimeout := 2500 * time.Millisecond
			if opt.Timeout > 0 && opt.Timeout < portTimeout {
				portTimeout = opt.Timeout
			}
			portCtx, portCancel := context.WithTimeout(raceCtx, portTimeout)
			defer portCancel()

			altSub, altBody, altErr := fetchSingleSubURL(portCtx, altURL, opt)
			if altErr == nil && altSub != nil && len(altSub.Servers) > 0 {
				winOnce.Do(func() {
					select {
					case resCh <- probeResult{sub: altSub, body: altBody, port: p}:
					default:
					}
					raceCancel()
				})
			} else {
				select {
				case resCh <- probeResult{err: altErr, port: p}:
				case <-raceCtx.Done():
				}
			}
		}(port)
	}

	// 启动首选高优先级候选端口
	launchProbe(candPorts[0])
	attemptIdx := 1
	staggerTicker := time.NewTicker(60 * time.Millisecond)
	defer staggerTicker.Stop()

	var firstErr error

	for {
		select {
		case <-ladderCtx.Done():
			return nil, nil, 0, fmt.Errorf("ladder probe exhausted across all candidate ports: %w", ladderCtx.Err())

		case <-staggerTicker.C:
			if attemptIdx < len(candPorts) {
				launchProbe(candPorts[attemptIdx])
				attemptIdx++
			} else {
				staggerTicker.Stop()
			}

		case res := <-resCh:
			if res.sub != nil {
				return res.sub, res.body, res.port, nil
			}
			if firstErr == nil && res.err != nil {
				firstErr = res.err
			}
			// 若当前端口快速失败，不等满 60ms 立即启动下一顺位候选端口
			if attemptIdx < len(candPorts) {
				launchProbe(candPorts[attemptIdx])
				attemptIdx++
			} else if activeProbes.Load() == 0 {
				if firstErr != nil {
					return nil, nil, 0, fmt.Errorf("ladder probe exhausted across all candidate ports: %w", firstErr)
				}
				return nil, nil, 0, errors.New("ladder probe exhausted across all candidate ports")
			}
		}
	}
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

	u, parseErr := url.Parse(rawURL)
	isZeroPort := parseErr == nil && (u.Port() == "" || u.Port() == "443" || u.Port() == "80") && strings.HasPrefix(u.Path, "/sub/")

	if isZeroPort {
		hostOnly := u.Hostname()
		scheme := u.Scheme
		if scheme == "" {
			scheme = "https"
		}

		// 1. 检查内存端口缓存：若之前已成功探测出非标工作端口，优先走缓存快照
		if cachedPort, ok := GetCachedSubPort(hostOnly); ok && cachedPort > 0 && cachedPort != 443 && cachedPort != 80 {
			cachedURL := fmt.Sprintf("%s://%s:%d%s", scheme, hostOnly, cachedPort, u.RequestURI())
			cachedTimeout := 2500 * time.Millisecond
			if opt.Timeout > 0 && opt.Timeout < cachedTimeout {
				cachedTimeout = opt.Timeout
			}
			cachedCtx, cachedCancel := context.WithTimeout(ctx, cachedTimeout)
			cSub, cBody, cErr := fetchSingleSubURL(cachedCtx, cachedURL, opt)
			cachedCancel()
			if cErr == nil && cSub != nil && len(cSub.Servers) > 0 {
				SaveLastBody(cBody)
				return cSub, nil
			}
			// 缓存端口失效（可能服务端换端口），剔除该缓存项并继续正常探测
			SetCachedSubPort(hostOnly, 0)
		}

		// 2. 主通道 443 探针：紧缩超时为 2.5s（或 opt.Timeout 较小值），防止在防火墙黑洞下死等 15s
		primaryTimeout := 2500 * time.Millisecond
		if opt.Timeout > 0 && opt.Timeout < primaryTimeout {
			primaryTimeout = opt.Timeout
		}
		primaryCtx, primaryCancel := context.WithTimeout(ctx, primaryTimeout)
		sub, body, err := fetchSingleSubURL(primaryCtx, rawURL, opt)
		primaryCancel()

		if err == nil && sub != nil && len(sub.Servers) > 0 {
			SetCachedSubPort(hostOnly, 443)
			SaveLastBody(body)
			return sub, nil
		}

		// 3. 主端口 443 遇阻，启动 RFC 8305 阶梯并发探测 StandardCandidatePorts
		altSub, altBody, winPort, ladderErr := probeCandidatePortsLadder(ctx, scheme, hostOnly, u.RequestURI(), opt)
		if ladderErr == nil && altSub != nil && len(altSub.Servers) > 0 {
			SetCachedSubPort(hostOnly, winPort)
			SaveLastBody(altBody)
			return altSub, nil
		}

		// 4. 判定致命状态：403 明确拒绝（到期或超额）清理缓存
		if err != nil && strings.Contains(err.Error(), "HTTP 403") {
			ClearLastBody()
			return nil, fmt.Errorf("subscription revoked or expired: %w", err)
		}
		if ladderErr != nil && strings.Contains(ladderErr.Error(), "HTTP 403") {
			ClearLastBody()
			return nil, fmt.Errorf("subscription revoked or expired: %w", ladderErr)
		}

		// 5. 尝试离线缓存兜底
		if !opt.DisableCache {
			if cached := LoadLastBody(); len(cached) > 0 {
				if lastSub, perr := ParseSubscriptionBytes(cached); perr == nil && len(lastSub.Servers) > 0 {
					return lastSub, nil
				}
			}
		}

		if ladderErr != nil {
			return nil, ladderErr
		}
		return nil, fmt.Errorf("fetch subscription failed on 443 and all candidate ports: %w", err)
	}

	// 显式非标端口订阅 URL：直接单目标请求，不触发阶梯并发探测
	sub, body, err := fetchSingleSubURL(ctx, rawURL, opt)
	if err == nil && sub != nil {
		SaveLastBody(body)
		return sub, nil
	}

	if err != nil && (strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "HTTP 404")) {
		ClearLastBody()
		return nil, fmt.Errorf("subscription revoked or expired: %w", err)
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
		Proxy: nil,
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err == nil {
				if parsedIP := net.ParseIP(host); parsedIP != nil {
					if isLocalOrPrivateIP(host, parsedIP) {
						return nil, fmt.Errorf("subscription to private or loopback IP %s is forbidden", host)
					}
				} else if getPhysicalDialerHook() == nil {
					if ip, rerr := resolvePhysicalIPv4(host); rerr == nil && ip != nil {
						addr = net.JoinHostPort(ip.String(), port)
					}
				}
			}
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

// 镜像对齐服务端 edge/sub.go 中的 SubServer 结构，绝不携带多余字段
type subServerForSign struct {
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

type subSignBodyForVerify struct {
	Version           string             `json:"version"`
	UserID            string             `json:"userId,omitempty"`
	ExpireAt          int64              `json:"expireAt,omitempty"`
	TrafficLimitBytes int64              `json:"trafficLimitBytes,omitempty"`
	Servers           []subServerForSign `json:"servers"`
	CreatedAt         int64              `json:"createdAt,omitempty"`
}

func verifySubscriptionSignature(sub *Subscription) error {
	if sub == nil || sub.Signature == "" {
		// 向后兼容：无签名旧订阅平滑放行
		return nil
	}
	if len(sub.Servers) == 0 || strings.TrimSpace(sub.Servers[0].Token) == "" {
		return fmt.Errorf("subscription signature present but primary server token missing")
	}

	signServers := make([]subServerForSign, len(sub.Servers))
	for i, s := range sub.Servers {
		signServers[i] = subServerForSign{
			Name:        s.Name,
			Host:        s.Host,
			Address:     s.Address,
			IP:          s.IP,
			Token:       s.Token,
			SNI:         s.SNI,
			Protocol:    s.Protocol,
			PinSPKI:     s.PinSPKI,
			LineType:    s.LineType,
			ISPAffinity: s.ISPAffinity,
			AltPorts:    s.AltPorts,
			ECH:         s.ECH,
			ECHConfig:   s.ECHConfig,
		}
	}

	body := subSignBodyForVerify{
		Version:           sub.Version,
		UserID:            sub.UserID,
		ExpireAt:          sub.ExpireAt,
		TrafficLimitBytes: sub.TrafficLimitBytes,
		Servers:           signServers,
		CreatedAt:         sub.CreatedAt,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("verify: marshal payload failed: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(sub.Servers[0].Token))
	mac.Write(data)
	expected := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(sub.Signature)) {
		return fmt.Errorf("ERR_SUB_TAMPERED: HMAC signature mismatch, node payload untrusted")
	}
	return nil
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
	if sub.Version != "aero/3.0" {
		return nil, fmt.Errorf("unsupported subscription version %q (expected aero/3.0)", sub.Version)
	}
	if err := verifySubscriptionSignature(&sub); err != nil {
		return nil, err
	}
	if err := sub.ValidateAndNormalize(); err != nil {
		return nil, fmt.Errorf("subscription validation failed: %w", err)
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
