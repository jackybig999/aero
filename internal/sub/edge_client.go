package sub

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 中台调用 edge 接口的唯一出口（组件只通过接口连接）。
// 节点使用真实域名 + Let's Encrypt 证书：一律按域名严格校验证书，密钥只放 Authorization 头，
// 不放 URL（会进入日志）。域名解析失败时可按 IP 直连，但 SNI 与证书校验仍用域名；没有域名的节点
// 无法校验身份，不发送密钥。

// edgeTLSConfig 可由测试替换（信任测试证书）；生产使用系统根证书。
var edgeTLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}

// edgeDial 可由测试替换（避免真实 DNS）。
var edgeDial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
}

var errEdgeNoDomain = errors.New("node has no domain; refusing to send credentials to an unverifiable peer")

// edgeDo 以 key 调用 edge 的 path，依次尝试域名与 IP；返回第一个建立连接的响应（调用方关闭 Body）。
func edgeDo(ctx context.Context, host, ip string, port int, method, path, key string, body []byte, timeout time.Duration) (*http.Response, error) {
	if host == "" || net.ParseIP(host) != nil {
		return nil, errEdgeNoDomain
	}
	if port <= 0 {
		port = 443
	}
	tlsCfg := edgeTLSConfig.Clone()
	tlsCfg.ServerName = host
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return edgeDial(ctx, network, addr, timeout)
			},
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	targets := []string{host}
	if ip != "" && ip != host {
		targets = append(targets, ip)
	}
	var lastErr error
	for _, tgt := range targets {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, "https://"+net.JoinHostPort(tgt, strconv.Itoa(port))+path, rd)
		if err != nil {
			return nil, err
		}
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("User-Agent", "AERO-Sub/1.0")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = fmt.Errorf("%s: %w", tgt, err)
	}
	return nil, lastErr
}

// ---- C13 远程管理接口（api/edge-remote.yaml）----

// errEdgeAPIUnavailable：节点返回伪装站（未开启 remote_admin_v1 或管理密钥不匹配）。
var errEdgeAPIUnavailable = errors.New("节点管理接口不可用：未开启 remote_admin_v1 或管理密钥不匹配")

type edgeRemoteStatus struct {
	NodeID      string       `json:"node_id"`
	Version     string       `json:"version"`
	Ready       bool         `json:"ready"`
	UptimeSec   int64        `json:"uptime_sec"`
	ListenPorts []int        `json:"listen_ports"`
	Cert        edgeCertInfo `json:"cert"`
	Sessions    struct {
		Active  int   `json:"active"`
		Tunnels int64 `json:"tunnels"`
	} `json:"sessions"`
	UsageAPI bool          `json:"usage_api"`
	Warp     edgeWarpState `json:"warp"`
	Host     struct {
		CPUPercent float64 `json:"cpu_percent"`
		Load1      float64 `json:"load1"`
		MemTotal   uint64  `json:"mem_total"`
		MemUsed    uint64  `json:"mem_used"`
		DiskTotal  uint64  `json:"disk_total"`
		DiskUsed   uint64  `json:"disk_used"`
	} `json:"host"`
}

type edgeCertInfo struct {
	Domain   string `json:"domain"`
	Issuer   string `json:"issuer"`
	NotAfter int64  `json:"not_after"`
	DaysLeft int    `json:"days_left"`
}

type edgeWarpState struct {
	Enabled   bool `json:"enabled"`
	All       bool `json:"all"`
	Available bool `json:"available"`
}

type edgeUsageState struct {
	Enabled     bool   `json:"enabled"`
	NodeID      string `json:"node_id"`
	MeteringKey string `json:"metering_key"`
}

// edgeAPI 以节点管理密钥调用 C13：in 非 nil 时作为 JSON 请求体，out 非 nil 时解码 JSON 响应。
func edgeAPI(ctx context.Context, ep EndpointInfo, method, path string, in, out any) error {
	if ep.AdminKey == "" {
		return errors.New("节点没有登记管理密钥")
	}
	var body []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = b
	}
	resp, err := edgeDo(ctx, ep.Host, ep.IP, ep.Port, method, path, ep.AdminKey, body, 8*time.Second)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/html") {
		return errEdgeAPIUnavailable
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var p struct {
			Code  string `json:"code"`
			Title string `json:"title"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p)
		return fmt.Errorf("%s %s: http %d %s %s", method, path, resp.StatusCode, p.Code, p.Title)
	}
	if out == nil {
		return nil
	}
	if !strings.HasPrefix(ct, "application/json") {
		return fmt.Errorf("%s %s: unexpected content type %q", method, path, ct)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// endpointFor 返回已安装节点的登记信息。
func (s *VPSService) endpointFor(vpsID uint64) (EndpointInfo, error) {
	if s.eps == nil {
		return EndpointInfo{}, errors.New("no endpoint store")
	}
	ep, ok := s.eps.Get(vpsID)
	if !ok || !ep.Installed {
		return EndpointInfo{}, fmt.Errorf("vps %d 未安装 edge", vpsID)
	}
	return ep, nil
}

// edgeCandidatePorts 与 edge 的 StandardCandidatePorts 顺序一致（C12，ADR-0005 端口轮试）。
var edgeCandidatePorts = []int{443, 2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443}

// portsFrom 返回以 first 开头、其后为其余候选端口的列表。
func portsFrom(first int) []int {
	out := make([]int, 0, len(edgeCandidatePorts)+1)
	if first > 0 {
		out = append(out, first)
	}
	for _, p := range edgeCandidatePorts {
		if p != first {
			out = append(out, p)
		}
	}
	return out
}

// RefreshEndpoint 经 C13 刷新节点登记（端口、版本、计量密钥）：依次尝试登记端口与候选端口
// （edge 遇端口被占用时会改用候选端口）。不登录节点、不读取节点文件；需要中台安装时登记的管理密钥。
func (s *VPSService) RefreshEndpoint(ctx context.Context, vpsID uint64) (*EndpointInfo, error) {
	if s.eps == nil {
		return nil, errors.New("no endpoint store")
	}
	ep, ok := s.eps.Get(vpsID)
	if !ok || ep.AdminKey == "" {
		return nil, fmt.Errorf("vps %d 没有中台登记的管理密钥：请经中台安装 edge", vpsID)
	}
	var lastErr error
	for _, p := range portsFrom(ep.Port) {
		try := ep
		try.Port = p
		var st edgeRemoteStatus
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := edgeAPI(attempt, try, http.MethodGet, "/admin/v1/status", nil, &st)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		ep.Port, ep.Version, ep.Installed = p, st.Version, true
		if len(st.ListenPorts) > 0 {
			ep.Port = st.ListenPorts[0]
		}
		ep.MeteringKey = ""
		if st.UsageAPI {
			var us edgeUsageState
			if err := edgeAPI(ctx, ep, http.MethodGet, "/admin/v1/usage-api", nil, &us); err == nil && us.Enabled {
				ep.MeteringKey = us.MeteringKey
			}
		}
		if err := s.eps.Upsert(ep); err != nil {
			return nil, err
		}
		return &ep, nil
	}
	return nil, fmt.Errorf("vps %d 管理接口不可达: %w", vpsID, lastErr)
}

// SetUsageAPI 开关节点 C6 计量（C13 PUT /admin/v1/usage-api），并登记返回的计量只读密钥。
func (s *VPSService) SetUsageAPI(ctx context.Context, vpsID uint64, enabled bool) (bool, error) {
	ep, err := s.endpointFor(vpsID)
	if err != nil {
		return false, err
	}
	var us edgeUsageState
	if err := edgeAPI(ctx, ep, http.MethodPut, "/admin/v1/usage-api", map[string]bool{"enabled": enabled}, &us); err != nil {
		return false, err
	}
	return us.Enabled, s.eps.SetMeteringKey(vpsID, us.MeteringKey)
}
