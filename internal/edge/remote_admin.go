package edge

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// C13 远程管理接口（api/edge-remote.yaml，ADR-0016）：中台管理节点的唯一通道。
// 只认 Authorization: Bearer <admin_key>；接口关闭、未鉴权、密钥错误或未知路径一律返回伪装站。
// 不提供执行命令、读写任意文件或修改宿主配置的能力；修改由 edge 校验后原子写入自身配置。

const (
	remoteAdminRatePerMinute = 120              // 契约：每个密钥 120 次/分钟
	purityForceInterval      = 10 * time.Minute // 契约：refresh 每 10 分钟至多一次
	remoteAdminBodyLimit     = 4 << 10
)

type remoteAdmin struct {
	s   *Server
	key []byte
	lim minuteLimiter
	now func() time.Time

	purityMu   sync.Mutex
	lastForced time.Time
}

func newRemoteAdmin(s *Server, adminKey string) *remoteAdmin {
	return &remoteAdmin{s: s, key: []byte(adminKey), lim: minuteLimiter{max: remoteAdminRatePerMinute}, now: time.Now}
}

// serve 处理 /admin/v1/*（调用方保证 a 非 nil）。
func (a *remoteAdmin) serve(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearerToken(r)
	if !ok || len(a.key) == 0 || subtle.ConstantTimeCompare([]byte(tok), a.key) != 1 {
		a.s.serveCover(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if retry := a.lim.take(a.now()); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeProblem(w, http.StatusTooManyRequests, "EDGE_RATE_LIMITED", "rate limited")
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /admin/v1/status":
		writeAPIJSON(w, a.s.remoteStatus())
	case "GET /admin/v1/purity":
		a.purity(w, r)
	case "GET /admin/v1/usage-api":
		writeAPIJSON(w, a.s.usageState())
	case "PUT /admin/v1/usage-api":
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if !decodeStrict(w, r, &req) || req.Enabled == nil {
			writeProblem(w, http.StatusBadRequest, "EDGE_BAD_REQUEST", "enabled is required")
			return
		}
		st, err := a.s.setUsageAPI(*req.Enabled)
		if err != nil {
			log.Printf("[ADMIN] usage-api: %v", err)
			writeProblem(w, http.StatusInternalServerError, "EDGE_INTERNAL", "internal error")
			return
		}
		writeAPIJSON(w, st)
	case "PUT /admin/v1/warp":
		var req struct {
			Enabled *bool `json:"enabled"`
			All     bool  `json:"all"`
		}
		if !decodeStrict(w, r, &req) || req.Enabled == nil {
			writeProblem(w, http.StatusBadRequest, "EDGE_BAD_REQUEST", "enabled is required")
			return
		}
		if *req.Enabled && !warpLocalProxyAvailable() {
			writeProblem(w, http.StatusConflict, "EDGE_WARP_UNAVAILABLE", "no local WARP proxy")
			return
		}
		if err := a.s.SetWarpEgress(*req.Enabled, req.All); err != nil {
			log.Printf("[ADMIN] warp: %v", err)
			writeProblem(w, http.StatusInternalServerError, "EDGE_INTERNAL", "internal error")
			return
		}
		writeAPIJSON(w, a.s.warpState())
	case "POST /admin/v1/cert/reload":
		ci, err := a.s.reloadCert()
		if err != nil {
			log.Printf("[ADMIN] cert reload: %v", err)
			writeProblem(w, http.StatusInternalServerError, "EDGE_INTERNAL", "certificate reload failed")
			return
		}
		writeAPIJSON(w, ci)
	case "POST /admin/v1/restart":
		w.WriteHeader(http.StatusAccepted)
		a.s.requestRestart()
	default:
		a.s.serveCover(w, r)
	}
}

func (a *remoteAdmin) purity(w http.ResponseWriter, r *http.Request) {
	force := false
	if r.URL.Query().Get("refresh") == "true" {
		a.purityMu.Lock()
		if now := a.now(); now.Sub(a.lastForced) >= purityForceInterval {
			force, a.lastForced = true, now
		}
		a.purityMu.Unlock()
	}
	if a.s.purityEngine == nil {
		writeProblem(w, http.StatusInternalServerError, "EDGE_INTERNAL", "purity engine unavailable")
		return
	}
	rep, err := a.s.purityEngine.Probe(r.Context(), force)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "EDGE_INTERNAL", "purity probe failed")
		return
	}
	writeAPIJSON(w, purityState{CheckedAt: rep.LastProbeAt.Unix(), EgressIPCountry: rep.IPCountry, Results: rep})
}

// decodeStrict 读取至多 4 KiB 的 JSON，拒绝未知字段（契约 additionalProperties: false）。
func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, remoteAdminBodyLimit))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil
}

// ---- 契约结构（api/edge-remote.yaml components.schemas） ----

type remoteStatus struct {
	NodeID      string        `json:"node_id"`
	Version     string        `json:"version"`
	Ready       bool          `json:"ready"`
	UptimeSec   int64         `json:"uptime_sec"`
	ListenPorts []int         `json:"listen_ports"`
	Cert        certInfo      `json:"cert"`
	Sessions    sessionCounts `json:"sessions"`
	UsageAPI    bool          `json:"usage_api"`
	Warp        warpState     `json:"warp"`
	Host        hostLoad      `json:"host"`
}

type sessionCounts struct {
	Active  int   `json:"active"`
	Tunnels int64 `json:"tunnels"`
}

type hostLoad struct {
	CPUPercent float64 `json:"cpu_percent"`
	Load1      float64 `json:"load1"`
	MemTotal   uint64  `json:"mem_total"`
	MemUsed    uint64  `json:"mem_used"`
	DiskTotal  uint64  `json:"disk_total"`
	DiskUsed   uint64  `json:"disk_used"`
}

type certInfo struct {
	Domain   string `json:"domain"`
	Issuer   string `json:"issuer"`
	NotAfter int64  `json:"not_after"`
	DaysLeft int    `json:"days_left"`
}

type purityState struct {
	CheckedAt       int64         `json:"checked_at"`
	EgressIPCountry string        `json:"egress_ip_country"`
	Results         *PurityReport `json:"results"`
}

type usageAPIState struct {
	Enabled     bool   `json:"enabled"`
	NodeID      string `json:"node_id"`
	MeteringKey string `json:"metering_key,omitempty"`
}

type warpState struct {
	Enabled   bool `json:"enabled"`
	All       bool `json:"all"`
	Available bool `json:"available"`
}

// ---- Server 侧操作 ----

func (s *Server) remoteStatus() remoteStatus {
	total, _ := s.quicServer.connTracker.Sessions()
	st := remoteStatus{
		Version:   Version,
		Ready:     s.ready.Load(),
		UptimeSec: int64(time.Since(s.startedAt).Seconds()),
		Cert:      s.certInfo(),
		Sessions:  sessionCounts{Active: total},
		Warp:      s.warpState(),
	}
	if s.connLimit != nil {
		st.Sessions.Tunnels = s.connLimit.Active()
	}
	us := s.usageState()
	st.NodeID, st.UsageAPI = us.NodeID, us.Enabled
	for _, addr := range append([]string{s.Addr()}, s.AltAddrs()...) {
		if _, p, err := net.SplitHostPort(addr); err == nil {
			if n, err := strconv.Atoi(p); err == nil && n > 0 {
				st.ListenPorts = append(st.ListenPorts, n)
			}
		}
	}
	if m := s.metricsCollector.GetMetrics(); m != nil {
		const mib = 1 << 20
		st.Host = hostLoad{CPUPercent: m.CPUUsagePct, Load1: m.LoadAverage[0], MemTotal: m.MemoryTotalMB * mib, MemUsed: m.MemoryUsedMB * mib}
	}
	st.Host.DiskTotal, st.Host.DiskUsed, _ = diskBytes(s.dataDir)
	return st
}

// certInfo 描述当前生效的证书。
func (s *Server) certInfo() certInfo {
	ci := certInfo{Domain: s.cfg.Domain}
	var c *tls.Certificate
	if s.certLoader != nil {
		c = s.certLoader.CurrentCert()
	} else {
		c = s.tlsCert
	}
	if c == nil || len(c.Certificate) == 0 {
		return ci
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return ci
	}
	ci.Issuer = leaf.Issuer.CommonName
	if ci.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		ci.Issuer = leaf.Issuer.Organization[0]
	}
	ci.NotAfter = leaf.NotAfter.Unix()
	ci.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	return ci
}

// reloadCert 重新加载证书；证书来自系统 ACME 默认位置时先重新查找（续期可能换了目录）。
func (s *Server) reloadCert() (certInfo, error) {
	if s.certLoader == nil {
		return certInfo{}, errors.New("no file-backed certificate")
	}
	certFile, keyFile := s.certLoader.Files()
	if s.certDiscovered {
		if c, ok := findSystemCert(systemCertDirs(), normalizeCertDomain(s.cfg.Domain), time.Now()); ok {
			certFile, keyFile = c.CertFile, c.KeyFile
		}
	}
	if err := s.certLoader.Reload(certFile, keyFile); err != nil {
		return certInfo{}, err
	}
	return s.certInfo(), nil
}

func (s *Server) warpState() warpState {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return warpState{Enabled: s.cfg.WarpProxy != "", All: s.cfg.WarpAll, Available: warpLocalProxyAvailable()}
}

func (s *Server) usageState() usageAPIState {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	st := usageAPIState{Enabled: s.usageMeter != nil, NodeID: s.cfg.NodeID}
	if st.Enabled {
		st.MeteringKey = s.cfg.MeteringKey
	}
	return st
}

// setUsageAPI 运行时开关 C6 计量：开启时生成缺失的密钥与节点标识、打开 usage.db 并开始计量；
// 关闭时停止计量并做最后一次落盘。先持久化配置，持久化失败则不改变运行状态。
func (s *Server) setUsageAPI(enabled bool) (usageAPIState, error) {
	s.cfgMu.Lock()
	if enabled == (s.usageMeter != nil) {
		s.cfgMu.Unlock()
		return s.usageState(), nil
	}
	cfg := s.cfg
	cfg.UsageAPI = enabled
	var meter *UsageMeter
	if enabled {
		if err := ensureUsageIdentity(&cfg); err != nil {
			s.cfgMu.Unlock()
			return usageAPIState{}, err
		}
		m, err := OpenUsageMeter(filepath.Join(s.dataDir, "usage.db"))
		if err != nil {
			s.cfgMu.Unlock()
			return usageAPIState{}, err
		}
		meter = m
	}
	if err := persistServerConfig(cfg); err != nil {
		if meter != nil {
			_ = meter.Close()
		}
		s.cfgMu.Unlock()
		return usageAPIState{}, fmt.Errorf("persist usage_api: %w", err)
	}
	s.cfg.UsageAPI, s.cfg.MeteringKey, s.cfg.NodeID = cfg.UsageAPI, cfg.MeteringKey, cfg.NodeID
	if enabled {
		s.startUsageLocked(meter)
	} else {
		s.stopUsageLocked()
	}
	s.cfgMu.Unlock()
	log.Printf("[USAGE] C6 metering %s via remote admin", map[bool]string{true: "enabled", false: "disabled"}[enabled])
	return s.usageState(), nil
}

// startUsageLocked 启用计量与 C6 接口并启动落盘协程（调用方持有 cfgMu）。
func (s *Server) startUsageLocked(m *UsageMeter) {
	s.usageMeter = m
	s.quicServer.SetUsageMeter(m)
	s.usageAPI.Store(newUsageAPI(m, s.cfg.MeteringKey, s.cfg.NodeID, s.nodeStatus))
	stop, done := make(chan struct{}), make(chan struct{})
	s.usageStop, s.usageDone = stop, done
	go func() {
		defer close(done)
		m.Run(stop)
	}()
}

// stopUsageLocked 停止计量：先摘除接口与数据路径钩子，再等落盘协程退出并关闭数据库（调用方持有 cfgMu）。
func (s *Server) stopUsageLocked() {
	if s.usageMeter == nil {
		return
	}
	s.usageAPI.Store(nil)
	s.quicServer.SetUsageMeter(nil)
	if s.usageStop != nil {
		close(s.usageStop)
		<-s.usageDone
		s.usageStop, s.usageDone = nil, nil
	}
	if err := s.usageMeter.Close(); err != nil {
		log.Printf("[USAGE] [ERROR] final flush: %v", err)
	}
	s.usageMeter = nil
}

// requestRestart 请求优雅重启：Run 排空后返回，进程退出，由服务单元 Restart=always 拉起。
func (s *Server) requestRestart() {
	s.restartOnce.Do(func() { close(s.restartCh) })
}
