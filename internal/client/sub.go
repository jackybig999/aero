// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
		LegacyServerName  string   `json:"serverName"`
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
	if s.SNI == "" {
		s.SNI = aux.LegacyServerName
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
	Signature         string         `json:"signature,omitempty" yaml:"sig"` // 已废弃（C5 §5）：读取但忽略
	Servers           []ServerConfig `json:"servers" yaml:"nodes"`
	CreatedAt         int64          `json:"createdAt,omitempty" yaml:"created_at"`
	Opt               Optimization   `json:"optimization,omitempty" yaml:"optimization"`

	// FromCache 为 true 表示本次拉取失败，结果取自本地缓存（上一次成功拉取的订阅）。
	// 启动时可以用它连上节点；token 刷新与 401 刷新必须把它视为“拉取失败”（缓存里的 token 不是新签发的）。
	FromCache bool `json:"-" yaml:"-"`
}

func (s *Subscription) UnmarshalJSON(data []byte) error {
	type Alias Subscription
	aux := struct {
		*Alias
		SnakeTrafficLimit int64 `json:"traffic_limit_bytes"`
		CamelTrafficLimit int64 `json:"trafficLimitBytes"`
		SnakeTrafficUsed  int64 `json:"traffic_used_bytes"`
		CamelTrafficUsed  int64 `json:"trafficUsedBytes"`
		SnakeExpireAt     int64 `json:"expire_at"`
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
	if s.ExpireAt == 0 {
		s.ExpireAt = aux.SnakeExpireAt
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

// subDefaultPort 是 C5 §3 规定的缺省端口（address 缺省或只有主机名时）。
const subDefaultPort = 443

// validPort 判断端口是否在 1-65535。
func validPort(p int) bool { return p >= 1 && p <= 65535 }

// normalizeNodeAddr 把节点地址规整为 host:port：只有主机名（或裸 IPv6）时补默认端口 443；端口必须是 1-65535 的十进制数。
func normalizeNodeAddr(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty address")
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		if h == "" {
			return "", fmt.Errorf("address %q has an empty host", raw)
		}
		n, perr := strconv.Atoi(p)
		if perr != nil || !validPort(n) {
			return "", fmt.Errorf("address %q has an invalid port (want 1-65535)", raw)
		}
		return net.JoinHostPort(h, strconv.Itoa(n)), nil
	}
	// 没有端口：只接受主机名或 IP 字面量（可带方括号的 IPv6）
	h := strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	if h == "" || strings.ContainsAny(h, " /\\?#@") {
		return "", fmt.Errorf("address %q is not a valid host", raw)
	}
	if strings.Contains(h, ":") && net.ParseIP(h) == nil {
		return "", fmt.Errorf("address %q is not a valid host:port", raw)
	}
	return net.JoinHostPort(h, strconv.Itoa(subDefaultPort)), nil
}

// normalizeServer 按 C5 §3 校验并规整单个节点；返回错误表示该节点非法。
func normalizeServer(srv *ServerConfig) error {
	srv.Name = strings.TrimSpace(srv.Name)
	srv.Host = strings.TrimSpace(srv.Host)
	srv.Address = strings.TrimSpace(srv.Address)
	if srv.Address == "" && srv.Host == "" {
		return errors.New("missing address and host")
	}
	if srv.Address == "" {
		srv.Address = srv.Host
	}
	addr, err := normalizeNodeAddr(srv.Address)
	if err != nil {
		return err
	}
	srv.Address = addr
	if srv.Host == "" {
		srv.Host, _, _ = net.SplitHostPort(addr)
	}
	if srv.Name == "" {
		srv.Name = srv.Address
	}
	if strings.TrimSpace(srv.Token) == "" {
		return errors.New("missing token")
	}
	srv.SNI = strings.TrimSpace(srv.SNI)
	if srv.SNI == "" {
		return errors.New("missing sni")
	}
	if srv.Protocol != "connect-ip" {
		return fmt.Errorf("unsupported protocol %q (want connect-ip)", srv.Protocol)
	}
	for _, cp := range srv.AltPorts {
		if !validPort(cp) {
			return fmt.Errorf("alt_ports contains invalid port %d (want 1-65535)", cp)
		}
	}
	return nil
}

// ValidateAndNormalize 按 C5 §3 校验并规整订阅。契约没有规定单个节点非法时整份拒绝，
// 所以非法节点被跳过并记录日志（不含 token）；一个有效节点都不剩时整份拒绝。
func (s *Subscription) ValidateAndNormalize() error {
	if s == nil || len(s.Servers) == 0 {
		return fmt.Errorf("empty subscription: no servers configured")
	}
	valid := make([]ServerConfig, 0, len(s.Servers))
	var firstErr error
	for i := range s.Servers {
		srv := s.Servers[i]
		if err := normalizeServer(&srv); err != nil {
			log.Printf("[SUB] skipping invalid server[%d] (%q): %v", i, srv.Name, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("server[%d] (%s): %w", i, srv.Name, err)
			}
			continue
		}
		var mainPort int
		if _, pStr, err := net.SplitHostPort(srv.Address); err == nil {
			mainPort, _ = strconv.Atoi(pStr)
		}
		// 若服务端未下发备用端口，主动注入高防备用端口池，保障自愈避障能力；同时过滤掉主端口与重复端口
		if len(srv.AltPorts) == 0 {
			candidates := StandardCandidatePorts
			if mainPort == subDefaultPort {
				srv.AltPorts = append([]int(nil), candidates...)
			} else {
				srv.AltPorts = []int{subDefaultPort}
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
				if cp != mainPort && !seen[cp] {
					seen[cp] = true
					filtered = append(filtered, cp)
				}
			}
			srv.AltPorts = filtered
		}
		// 若 IP 为空，尝试从 Host 中提取有效 IPv4 自动补齐，杜绝空值
		if srv.IP == "" {
			if ip := net.ParseIP(srv.Host); ip != nil && ip.To4() != nil {
				srv.IP = ip.String()
			}
		}
		// 跨系统 ECH 与 ECHConfig 双向归一化，杜绝跨系统命名失配
		if srv.ECH != "" && srv.ECHConfig == "" {
			srv.ECHConfig = srv.ECH
		} else if srv.ECHConfig != "" && srv.ECH == "" {
			srv.ECH = srv.ECHConfig
		}
		valid = append(valid, srv)
	}
	if len(valid) == 0 {
		return fmt.Errorf("no valid servers in subscription: %w", firstErr)
	}
	s.Servers = valid
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
	FromCache     bool // 订阅来自本地缓存而非本次成功拉取（见 Subscription.FromCache）
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
		FromCache:  s.FromCache,
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
	received := 0

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
			received++
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
			} else if received >= attemptIdx {
				// 每个已发射的探测恰好交回一个结果；不能用“活跃协程数为 0”判断——
				// 协程在发出结果之后才递减计数，最后一个结果先到时会误判为还有探测在跑，白等到总超时。
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

	// C5 §1：只通过 https:// 获取订阅；错误信息不回显完整 URL（路径里含订阅标识）。
	u, parseErr := url.Parse(rawURL)
	if parseErr != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" {
		scheme := "(none)"
		if parseErr == nil && u.Scheme != "" {
			scheme = u.Scheme + "://"
		}
		return nil, fmt.Errorf("invalid subscription URL: scheme %s is not allowed, only https:// with a host is accepted (C5 §1)", scheme)
	}
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
				SaveLastBody(rawURL, cBody)
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
			SaveLastBody(rawURL, body)
			return sub, nil
		}

		// 3. 主端口 443 遇阻，启动 RFC 8305 阶梯并发探测 StandardCandidatePorts
		altSub, altBody, winPort, ladderErr := probeCandidatePortsLadder(ctx, scheme, hostOnly, u.RequestURI(), opt)
		if ladderErr == nil && altSub != nil && len(altSub.Servers) > 0 {
			SetCachedSubPort(hostOnly, winPort)
			SaveLastBody(rawURL, altBody)
			return altSub, nil
		}

		// 4. 判定致命状态：403 明确拒绝（到期或超额）清理缓存
		if err != nil && strings.Contains(err.Error(), "HTTP 403") {
			ClearLastBody(rawURL)
			return nil, fmt.Errorf("subscription revoked or expired: %w", err)
		}
		if ladderErr != nil && strings.Contains(ladderErr.Error(), "HTTP 403") {
			ClearLastBody(rawURL)
			return nil, fmt.Errorf("subscription revoked or expired: %w", ladderErr)
		}

		// 5. 尝试离线缓存兜底
		if !opt.DisableCache {
			if lastSub := cachedSubscription(rawURL, ladderErr); lastSub != nil {
				return lastSub, nil
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
		SaveLastBody(rawURL, body)
		return sub, nil
	}

	if err != nil && (strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "HTTP 404")) {
		ClearLastBody(rawURL)
		return nil, fmt.Errorf("subscription revoked or expired: %w", err)
	}

	// 主 URL 失败时，尝试故障漂移
	if parseErr == nil && u.Path != "" && strings.HasPrefix(u.Path, "/sub/") {
		if cached := LoadLastBody(rawURL); len(cached) > 0 {
			if lastSub, perr := ParseSubscriptionBytes(cached); perr == nil && len(lastSub.Servers) > 0 {
				scheme := "https"
				for _, srv := range lastSub.Servers {
					altAddr := srv.Address
					if altAddr == "" || altAddr == u.Host {
						continue
					}
					altURL := fmt.Sprintf("%s://%s%s", scheme, altAddr, u.Path)
					if altSub, altBody, altErr := fetchSingleSubURL(ctx, altURL, opt); altErr == nil && altSub != nil {
						SaveLastBody(rawURL, altBody)
						return altSub, nil
					}
				}
			}
		}
	}

	if !opt.DisableCache {
		if lastSub := cachedSubscription(rawURL, err); lastSub != nil {
			return lastSub, nil
		}
	}

	return nil, fmt.Errorf("fetch subscription (all sources failed): %w", err)
}

// cachedSubscription 拉取失败后的离线兜底：读取该订阅 URL 自己的缓存，成功时返回带 FromCache 标记的订阅。
// 调用方必须检查 FromCache（启动可用它连节点；token 刷新、401 刷新要把它视为失败）。
func cachedSubscription(rawURL string, cause error) *Subscription {
	cached := LoadLastBody(rawURL)
	if len(cached) == 0 {
		return nil
	}
	lastSub, err := ParseSubscriptionBytes(cached)
	if err != nil || len(lastSub.Servers) == 0 {
		return nil
	}
	lastSub.FromCache = true
	log.Printf("[SUB] subscription fetch failed (%v); using the locally cached copy", cause)
	return lastSub
}

// maxSubscriptionBodyBytes 订阅响应体上限（4 MiB）；超出报错且不写缓存。
const maxSubscriptionBodyBytes = 4 << 20

// maxSubRedirects 订阅拉取最多跟随的重定向次数。
const maxSubRedirects = 3

// 只给测试用的钩子（生产默认值即安全值）：
//   - subAllowLoopbackForTest：放行回环地址（httptest 服务器在 127.0.0.1）；私网等其他地址仍然拒绝；
//   - subRootCAsForTest：自签测试证书的根池；设置后仍做完整的证书与主机名校验，只是信任的根不同；
//   - subLookupIPsForTest：替换主机名解析（测试 DNS 重绑定）。
var (
	subAllowLoopbackForTest atomic.Bool
	subRootCAsForTest       atomic.Pointer[x509.CertPool]
	subLookupIPsForTest     atomic.Pointer[func(ctx context.Context, host string) ([]net.IP, error)]
)

// subForbiddenIP 订阅请求不得到达的地址：回环、私网（10/8、172.16/12、192.168/16、fc00::/7）、
// 链路本地、未指定、组播、CGNAT 100.64/10、0/8、基准测试段 198.18/15（TUN 的 fake-IP 池也在这里）。
func subForbiddenIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() {
		return !subAllowLoopbackForTest.Load()
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 0:
			return true
		case ip4[0] == 100 && ip4[1]&0xC0 == 64: // 100.64.0.0/10
			return true
		case ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19): // 198.18.0.0/15
			return true
		}
	}
	return false
}

// subLookupIPs 解析订阅主机名：先走物理网卡的 DNS（避开 TUN 的 fake-IP），失败再退回系统解析器。
func subLookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	if fn := subLookupIPsForTest.Load(); fn != nil {
		return (*fn)(ctx, host)
	}
	if ip, err := resolvePhysicalIPv4(host); err == nil && ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	// IPv4 优先（物理拨号路径以 IPv4 为主）
	var v4, v6 []net.IP
	for _, a := range addrs {
		if a.IP.To4() != nil {
			v4 = append(v4, a.IP)
		} else {
			v6 = append(v6, a.IP)
		}
	}
	return append(v4, v6...), nil
}

// subCheckRemote 连接建立后再核对对端地址（兜住 physicalDialerHook 等无法事先得知目标 IP 的路径）。
func subCheckRemote(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	var ip net.IP
	switch a := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		return nil // 内存管道等没有 IP 的连接
	}
	if subForbiddenIP(ip) {
		return fmt.Errorf("subscription to private or loopback IP %s is forbidden", ip)
	}
	return nil
}

func subDialChecked(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := DialPhysicalDirect(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if cerr := subCheckRemote(conn); cerr != nil {
		_ = conn.Close()
		return nil, cerr
	}
	return conn, nil
}

// subDialContext 订阅拉取专用拨号：在解析之后、连接之前校验实际目标 IP，
// 因此对重定向、DNS 重绑定同样有效；之后只拨已校验的 IP 字面量，不再让系统二次解析。
func subDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("subscription dial: bad address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if subForbiddenIP(ip) {
			return nil, fmt.Errorf("subscription to private or loopback IP %s is forbidden", host)
		}
		return subDialChecked(ctx, network, addr)
	}
	if h := strings.TrimSuffix(strings.ToLower(host), "."); h == "localhost" || strings.HasSuffix(h, ".localhost") {
		if !subAllowLoopbackForTest.Load() {
			return nil, fmt.Errorf("subscription to private or loopback host %s is forbidden", host)
		}
	}
	if getPhysicalDialerHook() != nil {
		// 钩子自己负责解析与连接；连接建立后核对对端地址
		return subDialChecked(ctx, network, addr)
	}
	ips, err := subLookupIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("subscription dial: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("subscription dial: resolve %s: no addresses", host)
	}
	// 任何一条记录落在禁区就整体拒绝：不给“公网+私网混合记录”留空子
	for _, ip := range ips {
		if subForbiddenIP(ip) {
			return nil, fmt.Errorf("subscription host %s resolves to private or loopback IP %s: forbidden", host, ip)
		}
	}
	const maxTries = 4
	var lastErr error
	for i, ip := range ips {
		if i >= maxTries {
			break
		}
		conn, derr := subDialChecked(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// subCheckRedirect 重定向只允许 https 目标、最多 maxSubRedirects 次。
func subCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxSubRedirects {
		return fmt.Errorf("subscription redirected more than %d times", maxSubRedirects)
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("subscription redirect to non-https scheme %q is forbidden", req.URL.Scheme)
	}
	return nil
}

func fetchSingleSubURL(ctx context.Context, targetURL string, opt SubFetchOptions) (*Subscription, []byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, err
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" {
		return nil, nil, errors.New("subscription URL must use https:// with a host (C5 §1)")
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
		Proxy:                 nil,
		DialContext:           subDialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if pool := subRootCAsForTest.Load(); pool != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	defer tr.CloseIdleConnections() // 每次拉取新建 Transport，结束时关闭空闲连接，避免泄漏
	client := &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: subCheckRedirect,
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
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&errBody)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBodyBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read subscription body failed: %w", err)
	}
	if len(body) > maxSubscriptionBodyBytes {
		return nil, nil, fmt.Errorf("subscription body exceeds %d bytes", maxSubscriptionBodyBytes)
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
	if sub.Version != "aero/3.0" {
		return nil, fmt.Errorf("unsupported subscription version %q (expected aero/3.0)", sub.Version)
	}
	if err := sub.ValidateAndNormalize(); err != nil {
		return nil, fmt.Errorf("subscription validation failed: %w", err)
	}
	return &sub, nil
}

var lastBodyMu sync.RWMutex

// lastBodyPath 返回某个订阅 URL 的缓存文件路径：客户端数据目录下 .last-sub-<SHA-256 前 16 位十六进制>。
// 文件名不含 URL/token 明文；不同订阅各用各的文件，换订阅不会回退到上一个订阅的节点。
func lastBodyPath(subURL string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(subURL)))
	dir := GetDataDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, ".last-sub-"+hex.EncodeToString(sum[:8]))
}

// writeFileAtomic 先写同目录临时文件再 rename 替换，崩溃时只会看到旧文件或新文件，不会是半个文件。
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".last-sub-*.tmp")
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
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		return err
	}
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// SaveLastBody 本地保存该订阅 URL 最后一次成功拉取的有效订阅（0600，原子替换）。写失败只记录日志，不影响本次使用。
func SaveLastBody(subURL string, body []byte) {
	if len(body) == 0 {
		return
	}
	lastBodyMu.Lock()
	defer lastBodyMu.Unlock()
	p := lastBodyPath(subURL)
	if p == "" {
		log.Printf("[SUB] cannot cache subscription: no data directory")
		return
	}
	if err := writeFileAtomic(p, body); err != nil {
		log.Printf("[SUB] cannot cache subscription to %s: %v", filepath.Dir(p), err)
	}
}

// LoadLastBody 加载该订阅 URL 的本地缓存
func LoadLastBody(subURL string) []byte {
	lastBodyMu.RLock()
	defer lastBodyMu.RUnlock()
	p := lastBodyPath(subURL)
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}

// ClearLastBody 清理该订阅 URL 的本地缓存
func ClearLastBody(subURL string) {
	lastBodyMu.Lock()
	defer lastBodyMu.Unlock()
	if p := lastBodyPath(subURL); p != "" {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("[SUB] cannot remove cached subscription: %v", err)
		}
	}
}
