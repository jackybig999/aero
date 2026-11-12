// Copyright 2026 AERO Protocol Contributors
// AERO Native Subscription Builder, Edge Sync & SNI Matrix Subsystem
// Enforces:
// 1. Subscription format: /sub/{slug} (random per subscription; no fixed names)
// 2. 403 Forbidden if user is expired or switch_status is off
// 3. ServerName equals physical node domain, zero non-standard ports in subscription URLs
// 4. OpenAPI sync with Edge nodes via POST /admin/subs
package sub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ----------------------------------------------------------------------
// SubBuilder
// ----------------------------------------------------------------------

type SubBuilder struct {
	users  UserStore
	eps    *EndpointStore
	vps    VPSStore
	sniMgr *SNIMatrixManager

	issuer       *TokenIssuer // C3 签发方
	signedTokens bool         // 订阅下发签名 token（-signed-tokens，默认关闭）
}

// SetTokenIssuer 设置 C3 签发方；enabled 为真时订阅下发签名 token（替代旧的不透明 token）。
func (sb *SubBuilder) SetTokenIssuer(ti *TokenIssuer, enabled bool) {
	sb.issuer, sb.signedTokens = ti, enabled && ti != nil
}

func NewSubBuilder(users UserStore, eps *EndpointStore, vps VPSStore, sniMgr *SNIMatrixManager) *SubBuilder {
	return &SubBuilder{
		users:  users,
		eps:    eps,
		vps:    vps,
		sniMgr: sniMgr,
	}
}

func (sb *SubBuilder) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sub/{param}", sb.ServeSub)
	mux.HandleFunc("GET /api/v1/user/subscription", sb.ServePrivateSub)
}

func (sb *SubBuilder) ServePrivateSub(w http.ResponseWriter, r *http.Request) {
	uid, ok := r.Context().Value(CtxUserID).(uint64)
	if !ok || uid == 0 {
		writeJSON(w, http.StatusUnauthorized, errResp(1003, "unauthorized: login required"))
		return
	}
	user, err := sb.users.GetUser(uid)
	if err != nil || user == nil {
		writeJSON(w, http.StatusNotFound, errResp(1001, "user not found"))
		return
	}
	if !user.Status {
		writeJSON(w, http.StatusForbidden, errResp(1003, "account disabled"))
		return
	}
	if !user.IsStaff && !user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt) {
		writeJSON(w, http.StatusForbidden, errResp(1003, "subscription expired, please renew"))
		return
	}
	if !user.IsStaff && user.ExpireAt.IsZero() && user.PlanName == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"code": 0,
			"data": map[string]any{
				"slug":         user.SubSlug,
				"switchStatus": "off",
				"servers":      []any{},
				"sub_url":      "",
				"expireAt":     0,
				"limit_bytes":  0,
			},
		})
		return
	}

	isp := r.URL.Query().Get("isp")
	purpose := r.URL.Query().Get("purpose")
	allowDegrade := r.URL.Query().Get("allow_degrade") == "true"
	sb.writeUserSubscription(w, r, user, isp, purpose, allowDegrade)
}

func (sb *SubBuilder) ServeSub(w http.ResponseWriter, r *http.Request) {
	param := r.PathValue("param")
	if param == "" {
		param = strings.TrimPrefix(r.URL.Path, "/sub/")
		param = strings.Trim(param, "/")
	}
	if param == "" {
		http.NotFound(w, r)
		return
	}

	// 管理员与普通用户一样只能通过自身的随机 slug 访问；不存在按用户名或固定名称的入口。
	// 订阅 slug 格式：{username}{随机码}
	if sb.users != nil {
		// 优先从多订阅实体中检索
		if sub, err := sb.users.GetSubscriptionBySlug(param); err == nil && sub != nil {
			if !sub.Status || sub.SwitchStatus == "off" {
				http.Error(w, `{"code": 1003, "message": "subscription disabled"}`, http.StatusForbidden)
				return
			}
			if !sub.ExpireAt.IsZero() && time.Now().After(sub.ExpireAt) {
				http.Error(w, `{"code": 1003, "message": "subscription expired"}`, http.StatusForbidden)
				return
			}
			u, err := sb.users.GetUser(sub.UserID)
			if err != nil || u == nil {
				http.Error(w, `{"code": 1004, "message": "user deleted or not found"}`, http.StatusNotFound)
				return
			}
			if !u.Status {
				http.Error(w, `{"code": 1003, "message": "account disabled"}`, http.StatusForbidden)
				return
			}
			uname := ""
			uuid := sub.UserUUID
			if u != nil {
				uname = u.Username
				if uuid == "" {
					uuid = u.UUID
				}
			}
			virtualUser := &User{
				ID:            sub.UserID,
				UUID:          uuid,
				Username:      uname,
				SubSlug:       sub.SubSlug,
				SubToken:      sub.SubToken,
				SubTicketSeed: sub.SubTicketSeed,
				AssignedNodes: sub.AssignedNodes,
				ExpireAt:      sub.ExpireAt,
				Status:        sub.Status,
				CreatedAt:     sub.CreatedAt,
			}
			isp := r.URL.Query().Get("isp")
			purpose := r.URL.Query().Get("purpose")
			allowDegrade := r.URL.Query().Get("allow_degrade") == "true"
			sb.writeUserSubscription(w, r, virtualUser, isp, purpose, allowDegrade)
			return
		}

		if user, err := sb.users.GetUserBySlug(param); err == nil && user != nil {
			if !user.Status {
				http.Error(w, `{"code": 1003, "message": "account disabled"}`, http.StatusForbidden)
				return
			}
			if !user.IsStaff && !user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt) {
				http.Error(w, `{"code": 1003, "message": "subscription expired"}`, http.StatusForbidden)
				return
			}
			isp := r.URL.Query().Get("isp")
			purpose := r.URL.Query().Get("purpose")
			allowDegrade := r.URL.Query().Get("allow_degrade") == "true"
			sb.writeUserSubscription(w, r, user, isp, purpose, allowDegrade)
			return
		}
	}

	http.NotFound(w, r)
}

func (sb *SubBuilder) BuildSubscriptionDoc(user *User, isp, purpose string, allowDegrade bool) (map[string]any, int, error) {
	// C3：同一订阅在所有节点使用同一个签名 token（edge 以 uid 计设备数）
	signedToken := ""
	if sb.signedTokens {
		tok, _, err := sb.issuer.IssueForUser(user)
		if errors.Is(err, errSubscriptionExpired) {
			return nil, http.StatusForbidden, err
		}
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("issue token: %w", err)
		}
		signedToken = tok
	}
	vpsMap := make(map[uint64]*VPSHost)
	if sb.vps != nil {
		if hosts, err := sb.vps.List(); err == nil {
			for _, h := range hosts {
				vpsMap[h.ID] = h
			}
		}
	}

	type scoredServer struct {
		srv       map[string]any
		loadScore float64
		isTier1   bool
	}

	var candidates []scoredServer

	if sb.eps != nil {
		for _, ep := range sb.eps.List() {
			if !ep.Installed {
				continue
			}
			host := strings.TrimSpace(ep.Host)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if host == "" || net.ParseIP(host) != nil {
				continue
			}
			name := ep.Name
			if name == "" {
				name = fmt.Sprintf("VPS-%d", ep.VPSID)
			}

			// 如果用户配置了专属指定节点，且当前节点不在名单中，则跳过
			if len(user.AssignedNodes) > 0 {
				matched := false
				for _, an := range user.AssignedNodes {
					if strings.EqualFold(an, name) || strings.EqualFold(an, host) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			port := ep.Port
			if port <= 0 {
				port = 443
			}

			token := signedToken
			if token == "" && user.SubToken != "" {
				token = user.SubToken
			} else if token == "" && user.SubTicketSeed != "" {
				token = DeriveNodeToken(user.SubTicketSeed, host)
			}
			if token == "" {
				continue // 没有凭证的用户不下发节点（旧实现回退为可猜的 "usr_"+用户名）
			}

			loadScore := 50.0
			isTier1 := false
			vps := vpsMap[ep.VPSID]
			if vps == nil && ep.IP != "" {
				for _, hst := range vpsMap {
					if hst.IP == ep.IP {
						vps = hst
						break
					}
				}
			}

			if sb.vps != nil {
				if vps == nil || vps.Status != "online" {
					continue
				}
				if vps.Metrics != nil && !vps.Metrics.ProbeOK {
					loadScore = 90.0 // 边缘服务在线但底层 SSH 探针遇阻（如 SSH 端口安全限制），降权保留，杜绝商用多节点暴毙
				}
			}

			nodeIP := ep.IP
			if nodeIP == "" && vps != nil {
				nodeIP = vps.IP
			}

			ispAffinity := "ANY"
			if vps != nil {
				lowerRemark := strings.ToLower(vps.Remark + " " + vps.Name)
				if strings.Contains(lowerRemark, "cn2") || strings.Contains(lowerRemark, "电信") || strings.Contains(lowerRemark, "ct") {
					ispAffinity = "CT"
				} else if strings.Contains(lowerRemark, "9929") || strings.Contains(lowerRemark, "4837") || strings.Contains(lowerRemark, "联通") || strings.Contains(lowerRemark, "cu") {
					ispAffinity = "CU"
				} else if strings.Contains(lowerRemark, "cmin2") || strings.Contains(lowerRemark, "移动") || strings.Contains(lowerRemark, "cm") {
					ispAffinity = "CM"
				} else {
					ispAffinity = "BGP"
				}
			}

			// 候选备选端口池 (覆盖常见的标准 443 及完整候选端口池)
			var altPorts []int
			allCandidates := []int{443, 2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443}
			for _, cp := range allCandidates {
				if cp != port {
					altPorts = append(altPorts, cp)
				}
			}

			// 方案 A 物理域名锁死: ServerName 始终等于物理节点域名
			srv := map[string]any{
				"name":         name,
				"host":         host,
				"address":      fmt.Sprintf("%s:%d", host, port),
				"ip":           nodeIP,
				"token":        token,
				"sni":          host,
				"serverName":   host,
				"pin_spki":     []string{},
				"line_type":    "direct",
				"isp_affinity": ispAffinity,
				"protocol":     "connect-ip",
				"ech":          ep.ECH(),
				"ech_config":   ep.ECH(),
				"alt_ports":    altPorts,
			}
			if vps != nil {
				srv["purityScore"] = vps.PurityScore
				srv["aiBlocked"] = vps.AIBlocked
				if !vps.AIBlocked && vps.PurityScore >= 90 && !vps.IsWARPEgress {
					isTier1 = true
				}
				if vps.Metrics != nil && vps.Metrics.ProbeOK {
					latScore := float64(vps.Metrics.LatencyMS) / 10.0
					if latScore > 100 {
						latScore = 100
					}
					loadScore = vps.Metrics.CPUPercent*0.4 + vps.Metrics.MemPercent*0.3 + latScore*0.3
				}
			}

			candidates = append(candidates, scoredServer{
				srv:       srv,
				loadScore: loadScore,
				isTier1:   isTier1,
			})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].loadScore < candidates[j].loadScore
	})

	var allServers []map[string]any
	var tier1Servers []map[string]any
	for _, c := range candidates {
		allServers = append(allServers, c.srv)
		if c.isTier1 {
			tier1Servers = append(tier1Servers, c.srv)
		}
	}

	var servers []map[string]any
	var riskWarning string

	if purpose == "ai" {
		if len(tier1Servers) > 0 {
			servers = tier1Servers
		} else {
			if !allowDegrade {
				return nil, http.StatusServiceUnavailable, fmt.Errorf("TIER1_AI_NODES_EXHAUSTED")
			}
			servers = allServers
			riskWarning = "dirty_ip_degraded"
		}
	} else {
		servers = allServers
	}

	if servers == nil {
		servers = []map[string]any{}
	}

	expireUnix := int64(0)
	if user.IsStaff {
		expireUnix = 0
	} else if !user.ExpireAt.IsZero() {
		expireUnix = user.ExpireAt.Unix()
	} else {
		expireUnix = 0
	}

	// 规则 P9 零非标端口铁律：严格使用标准 443 HTTPS 域名链接，严禁出现非标端口
	subUrl := ""
	slugToUse := user.SubSlug

	if len(servers) > 0 {
		for _, srv := range servers {
			if addr, ok := srv["address"].(string); ok && addr != "" {
				host := addr
				if h, _, err := net.SplitHostPort(addr); err == nil {
					host = h
				}
				if host != "" && net.ParseIP(host) == nil {
					if slugToUse != "" {
						subUrl = fmt.Sprintf("https://%s/sub/%s", host, slugToUse)
						break
					}
				}
			}
		}
	}
	if subUrl == "" && slugToUse != "" {
		subUrl = fmt.Sprintf("https://domain.com/sub/%s", slugToUse)
	}

	doc := map[string]any{
		"version":          "aero/3.0",
		"userId":           user.Username,
		"slug":             user.SubSlug,
		"sub_url":          subUrl,
		"subUrl":           subUrl,
		"token":            user.SubToken,
		"subTicketSeed":    user.SubTicketSeed,
		"expireAt":         expireUnix,
		"expire_at":        expireUnix,
		"switchStatus":     "on",
		"createdAt":        user.CreatedAt.Unix(),
		"protocolPriority": []string{"connect-ip:443"},
		"servers":          servers,
		"optimization": map[string]any{
			"defaultQoS": "ultra-low-latency",
			"ispMatched": isp,
			"purpose":    purpose,
		},
	}
	if user.IsStaff {
		doc["role"] = "superadmin"
		doc["unrestricted"] = true
	}
	if riskWarning != "" {
		doc["riskWarning"] = riskWarning
	}

	return doc, http.StatusOK, nil
}

func (sb *SubBuilder) writeUserSubscription(w http.ResponseWriter, r *http.Request, user *User, isp, purpose string, allowDegrade bool) {
	doc, status, err := sb.BuildSubscriptionDoc(user, isp, purpose, allowDegrade)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":  status,
			"error": err.Error(),
		})
		return
	}

	// 动态适配请求方的公网访问域名 (过滤非标端口与纯 IP，自适应反代)
	if r != nil {
		pubHost := r.Header.Get("X-Forwarded-Host")
		if idx := strings.Index(pubHost, ","); idx != -1 {
			pubHost = pubHost[:idx]
		}
		pubHost = strings.TrimSpace(pubHost)
		if pubHost == "" {
			pubHost = r.Host
			if idx := strings.Index(pubHost, ","); idx != -1 {
				pubHost = pubHost[:idx]
			}
			pubHost = strings.TrimSpace(pubHost)
		}
		if h, _, err := net.SplitHostPort(pubHost); err == nil {
			pubHost = h
		}
		if pubHost != "" && net.ParseIP(pubHost) == nil && pubHost != "localhost" && strings.Contains(pubHost, ".") && !strings.Contains(pubHost, ":") && !strings.Contains(pubHost, ",") {
			newSubUrl := fmt.Sprintf("https://%s/sub/%s", pubHost, user.SubSlug)
			doc["sub_url"] = newSubUrl
			doc["subUrl"] = newSubUrl
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// ----------------------------------------------------------------------
// Edge OpenAPI Synchronizer: Sync credentials to Edge via POST /admin/subs
// ----------------------------------------------------------------------

type EdgeUserSubPayload struct {
	Username string `json:"username"`
	Slug     string `json:"slug"`
	Token    string `json:"token"`
	ExpireAt int64  `json:"expire_at"`
}

type EdgeUpsertSubsReq struct {
	Subs []EdgeUserSubPayload `json:"subs"`
}

func (s *VPSService) SyncUsersToEdge(vpsID uint64, users []*User) error {
	if s.eps == nil {
		return fmt.Errorf("no endpoint store")
	}
	ep, ok := s.eps.Get(vpsID)
	if !ok || !ep.Installed || ep.Host == "" {
		return fmt.Errorf("vps %d not installed or has no host", vpsID)
	}

	port := ep.Port
	if port <= 0 {
		port = 443
	}

	var payloads []EdgeUserSubPayload
	for _, u := range users {
		if u == nil || !u.Status || u.SubSlug == "" {
			continue
		}
		exp := int64(0)
		if !u.ExpireAt.IsZero() {
			exp = u.ExpireAt.Unix()
		}
		payloads = append(payloads, EdgeUserSubPayload{
			Username: u.Username,
			Slug:     u.SubSlug,
			Token:    u.SubToken,
			ExpireAt: exp,
		})
	}
	if len(payloads) == 0 {
		return nil
	}

	body, err := json.Marshal(EdgeUpsertSubsReq{Subs: payloads})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := edgeDo(ctx, ep.Host, ep.IP, port, http.MethodPost, "/admin/subs", ep.AdminKey, body, 5*time.Second)
	if err != nil {
		return fmt.Errorf("sync subs to vps %d: %w", vpsID, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("sync subs to vps %d: http %d", vpsID, resp.StatusCode)
	}
	return nil
}

func (s *VPSService) SyncAllUsersToVPS(vpsID uint64, userStore UserStore) error {
	if userStore == nil {
		return nil
	}
	users, _, err := userStore.ListUsers(1, 1000)
	if err != nil || len(users) == 0 {
		return err
	}
	userPtrs := make([]*User, len(users))
	for i := range users {
		userPtrs[i] = &users[i]
	}
	return s.SyncUsersToEdge(vpsID, userPtrs)
}

func (s *VPSService) BroadcastAllUsersToAllEdges(userStore UserStore) {
	if s.eps == nil || userStore == nil {
		return
	}
	users, _, err := userStore.ListUsers(1, 1000)
	if err != nil || len(users) == 0 {
		return
	}
	userPtrs := make([]*User, len(users))
	for i := range users {
		userPtrs[i] = &users[i]
	}
	for _, ep := range s.eps.List() {
		if ep.Installed && ep.Host != "" {
			_ = s.SyncUsersToEdge(ep.VPSID, userPtrs)
		}
	}
}

// ----------------------------------------------------------------------
// SNI Matrix Configuration & Manager
// ----------------------------------------------------------------------

const defaultSNIMatrixJSON = `{
  "version": "1.0.0",
  "providers": {
    "china_telecom": {
      "name": "中国电信",
      "default_sni": "edge.microsoft.com",
      "routes": {
        "JP": ["edge.microsoft.com", "gateway.icloud.com", "swdist.apple.com"],
        "HK": ["live.azure.com", "teams.microsoft.com", "edge.microsoft.com"],
        "US": ["edge.microsoft.com", "live.azure.com"],
        "DE": ["edge.microsoft.com", "gateway.icloud.com"],
        "DEFAULT": ["edge.microsoft.com", "gateway.icloud.com"]
      }
    },
    "china_unicom": {
      "name": "中国联通",
      "default_sni": "gateway.icloud.com",
      "routes": {
        "JP": ["gateway.icloud.com", "swdist.apple.com", "edge.microsoft.com"],
        "HK": ["gateway.icloud.com", "edge.microsoft.com"],
        "DE": ["gateway.icloud.com", "edge.microsoft.com"],
        "US": ["gateway.icloud.com", "edge.microsoft.com"],
        "DEFAULT": ["gateway.icloud.com", "edge.microsoft.com"]
      }
    },
    "china_mobile": {
      "name": "中国移动",
      "default_sni": "live.azure.com",
      "routes": {
        "HK": ["live.azure.com", "edge.microsoft.com", "s3.ap-east-1.amazonaws.com"],
        "SG": ["live.azure.com", "edge.microsoft.com"],
        "JP": ["live.azure.com", "swdist.apple.com"],
        "DEFAULT": ["live.azure.com", "edge.microsoft.com"]
      }
    },
    "default": {
      "name": "通用网络",
      "default_sni": "edge.microsoft.com",
      "routes": {
        "DEFAULT": ["edge.microsoft.com", "gateway.icloud.com", "live.azure.com"]
      }
    }
  }
}`

type SNIRouteMap map[string][]string

type SNIProviderConfig struct {
	Name       string      `json:"name"`
	DefaultSNI string      `json:"default_sni"`
	Routes     SNIRouteMap `json:"routes"`
}

type SNIMatrixConfig struct {
	Version   string                       `json:"version"`
	Providers map[string]SNIProviderConfig `json:"providers"`
}

type SNIMatrixManager struct {
	mu     sync.RWMutex
	path   string
	config SNIMatrixConfig
}

func NewSNIMatrixManager(path string) *SNIMatrixManager {
	m := &SNIMatrixManager{path: path}
	_ = json.Unmarshal([]byte(defaultSNIMatrixJSON), &m.config)
	if path != "" {
		_ = m.LoadFile(path)
	}
	return m
}

func (m *SNIMatrixManager) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg SNIMatrixConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.path = path
	m.config = cfg
	return nil
}

// ECH returns the Encrypted Client Hello configuration if present.
func (ep EndpointInfo) ECH() string {
	return ep.ECHConfig
}
