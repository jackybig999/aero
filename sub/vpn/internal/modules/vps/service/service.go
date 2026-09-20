package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/cloudflare"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/secret"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/sshprobe"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

// Service is VPS asset management only — no AERO install.
type Service struct {
	store store.Store
	box   *secret.Box
	cf    *cloudflare.Client
}

func New(s store.Store, box *secret.Box) *Service {
	return &Service{store: s, box: box, cf: cloudflare.NewFromEnv()}
}

func (s *Service) SetCloudflareClient(cf *cloudflare.Client) {
	s.cf = cf
}

func (s *Service) Create(p domain.CreateVPSParams) (*domain.VPSHost, error) {
	p.IP = strings.TrimSpace(p.IP)
	p.Name = strings.TrimSpace(p.Name)
	p.SSHPassword = strings.TrimSpace(p.SSHPassword)
	p.SSHUsername = strings.TrimSpace(p.SSHUsername)
	p.Domain = strings.TrimSpace(p.Domain)
	if p.Name == "" || p.IP == "" {
		return nil, fmt.Errorf("name and ip required")
	}
	if p.Domain == "" {
		return nil, fmt.Errorf("域名为必填项：严禁未绑定域名的 VPS 接入中台，杜绝源站 IP 泄露")
	}
	if net.ParseIP(p.Domain) != nil || !strings.Contains(p.Domain, ".") {
		return nil, fmt.Errorf("域名格式不合法：%s 不是有效的公网域名（严禁使用纯 IP 作为域名）", p.Domain)
	}

	// 域名与 IP 一致性复核（若在 CF 且未解析则自动写入灰云 A 记录）
	if err := s.VerifyOrSyncDomain(context.Background(), p.Domain, p.IP); err != nil {
		return nil, err
	}
	if p.SSHPort <= 0 {
		p.SSHPort = 22
	}
	if p.SSHUsername == "" {
		p.SSHUsername = "root"
	}
	if p.Role == "" {
		p.Role = "node"
	}
	if p.SSHPassword == "" {
		return nil, fmt.Errorf("ssh_password required")
	}
	// AES-GCM ciphertext at rest — never store plaintext password
	cipher, err := s.box.Encrypt(p.SSHPassword)
	if err != nil {
		return nil, fmt.Errorf("encrypt password: %w", err)
	}
	h := &domain.VPSHost{
		Name: p.Name, Role: p.Role, IP: p.IP,
		SSHPort: p.SSHPort, SSHUsername: p.SSHUsername,
		Domain: p.Domain, Remark: p.Remark, Status: "registered",
	}
	if _, err := s.store.Create(h, cipher); err != nil {
		return nil, err
	}
	// wipe plain from stack-ish; response host has no password field
	p.SSHPassword = ""
	return h, nil
}

func (s *Service) List() ([]domain.VPSHost, error) { return s.store.List() }

func (s *Service) Get(id uint64) (*domain.VPSHost, error) {
	h, _, err := s.store.Get(id)
	return h, err
}

func (s *Service) Delete(id uint64) error {
	// VPS module only deletes registry — does NOT touch AERO on the host.
	return s.store.Delete(id)
}

func (s *Service) UpdatePassword(id uint64, plain string) error {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return fmt.Errorf("password required")
	}
	cipher, err := s.box.Encrypt(plain)
	if err != nil {
		return err
	}
	return s.store.SetPassword(id, cipher)
}

// RepairIP restores missing IP into durable store (encrypted).
func (s *Service) RepairIP(id uint64, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip required")
	}
	// Optional interface: FileStore has SetHostIP
	type ipSetter interface {
		SetHostIP(id uint64, ip string) error
	}
	if fs, ok := s.store.(ipSetter); ok {
		return fs.SetHostIP(id, ip)
	}
	// fallback: recreate not available — error
	return fmt.Errorf("store does not support IP repair")
}

// Credentials decrypts password for AERO package jobs (via ProviderAdapter).
func (s *Service) Credentials(id uint64) (*domain.Credentials, error) {
	h, blob, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	pass, err := s.box.Decrypt(blob)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return &domain.Credentials{
		VPSID: h.ID, Name: h.Name, IP: h.IP, SSHPort: h.SSHPort,
		SSHUsername: h.SSHUsername, SSHPassword: pass, Domain: h.Domain,
	}, nil
}

func (s *Service) Probe(id uint64) (*domain.HostMetrics, error) {
	h, blob, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	pass, err := s.box.Decrypt(blob)
	if err != nil {
		m := &domain.HostMetrics{ProbeOK: false, ProbeError: "decrypt failed", Source: "none", CollectedAt: time.Now()}
		_ = s.store.UpdateMetrics(id, m, "offline")
		return m, err
	}
	if pass == "" {
		m := &domain.HostMetrics{ProbeOK: false, ProbeError: "no password", Source: "none", CollectedAt: time.Now()}
		_ = s.store.UpdateMetrics(id, m, "offline")
		return m, fmt.Errorf("no password")
	}
	start := time.Now()
	client, err := sshprobe.Dial(sshprobe.Credentials{
		Host: h.IP, Port: h.SSHPort, User: h.SSHUsername, Password: pass,
	}, 12*time.Second)
	if err != nil {
		m := &domain.HostMetrics{
			ProbeOK: false, ProbeError: err.Error(), Source: "ssh",
			CollectedAt: time.Now(), LatencyMS: time.Since(start).Milliseconds(),
		}
		_ = s.store.UpdateMetrics(id, m, "offline")
		return m, err
	}
	defer client.Close()
	met, err := sshprobe.CollectMetrics(client)
	if err != nil {
		m := &domain.HostMetrics{
			ProbeOK: false, ProbeError: err.Error(), Source: "ssh",
			CollectedAt: time.Now(), LatencyMS: time.Since(start).Milliseconds(),
		}
		_ = s.store.UpdateMetrics(id, m, "error")
		return m, err
	}
	if rx, tx, nerr := sshprobe.CollectNetDelta(client); nerr == nil {
		met.NetRxMbps, met.NetTxMbps = rx, tx
	}
	met.LatencyMS = time.Since(start).Milliseconds()
	met.ProbeOK = true
	_ = s.store.UpdateMetrics(id, met, "online")
	score, tier, state := CalculateCapacity(met)
	_ = s.store.UpdateCapacity(id, score, tier, state)
	return met, nil
}

// UpdateMeta 更新 VPS 主机元数据 (名称/备注/角色/SSH端口/用户)
func (s *Service) UpdateMeta(id uint64, p domain.UpdateVPSParams) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Role = strings.TrimSpace(p.Role)
	p.Remark = strings.TrimSpace(p.Remark)
	p.SSHUsername = strings.TrimSpace(p.SSHUsername)
	return s.store.UpdateMeta(id, p)
}

// ProbeAll 并发探测所有 VPS 资产 (限制最大 5 并发)，更新指标与健康容量打分
func (s *Service) ProbeAll(ctx context.Context) ([]domain.VPSHost, error) {
	hosts, err := s.store.List()
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return hosts, nil
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for _, h := range hosts {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				_, _ = s.Probe(id)
			case <-ctx.Done():
				return
			}
		}(h.ID)
	}
	wg.Wait()
	return s.store.List()
}

// CalculateCapacity 根据 VPS 主机指标综合评估健康与容量评分 (0~100) 与档位
func CalculateCapacity(m *domain.HostMetrics) (score int, tier int, state string) {
	if m == nil || !m.ProbeOK {
		return 0, 1, "offline"
	}
	// 1. 档位划分 (依据物理内存)
	tier = 2
	if m.MemTotalMB > 0 {
		if m.MemTotalMB <= 1200 {
			tier = 1 // Nano/Edge (<=1GB)
		} else if m.MemTotalMB > 4500 {
			tier = 3 // Enterprise (>4GB)
		}
	}

	// 2. 动态健康分基准 100 分
	s := 100.0
	if m.MemPercent > 90 {
		s -= 45
	} else if m.MemPercent > 80 {
		s -= 30
	} else if m.MemPercent > 70 {
		s -= 15
	}

	if m.CPUPercent > 90 {
		s -= 40
	} else if m.CPUPercent > 75 {
		s -= 25
	} else if m.CPUPercent > 50 {
		s -= 10
	}

	if m.LatencyMS > 400 {
		s -= 20
	} else if m.LatencyMS > 250 {
		s -= 10
	} else if m.LatencyMS > 150 {
		s -= 5
	}

	if s < 0 {
		s = 0
	}
	score = int(s)

	switch {
	case score >= 80:
		state = "excellent"
	case score >= 60:
		state = "good"
	case score >= 40:
		state = "heavy"
	default:
		state = "overload"
	}
	return score, tier, state
}


// Cloudflare IPv4 官方代理 IP 范围 (用于识别是否误开启了 CDN 橙色云朵)
var cfProxyCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

func isCloudflareProxyIP(ipStr string) bool {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}
	for _, cidr := range cfProxyCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

type DomainVerifyResult struct {
	Domain      string   `json:"domain"`
	TargetIP    string   `json:"target_ip"`
	ResolvedIPs []string `json:"resolved_ips"`
	Matched     bool     `json:"matched"`
	IsCFProxy   bool     `json:"is_cf_proxy"`
	CFSynced    bool     `json:"cf_synced"`
	StatusText  string   `json:"status_text"`
}

func (s *Service) CFStatus() map[string]any {
	enabled := s.cf != nil && s.cf.Enabled()
	return map[string]any{
		"enabled":          enabled,
		"token_configured": enabled,
	}
}

func (s *Service) UpdateDomain(ctx context.Context, id uint64, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	h, err := s.Get(id)
	if err != nil {
		return err
	}
	if err := s.VerifyOrSyncDomain(ctx, domain, h.IP); err != nil {
		return err
	}
	return s.store.UpdateDomain(id, domain)
}

// VerifyOrSyncDomain 校验域名与 IP 的解析一致性；若不一致但配置了 Cloudflare，自动写入灰云 A 记录 (proxied: false)
func (s *Service) VerifyOrSyncDomain(ctx context.Context, domain, ip string) error {
	_, err := s.VerifyOrSyncDomainDetail(ctx, domain, ip)
	return err
}

// VerifyOrSyncDomainDetail 返回详细的 DNS 解析复核与 CF 同步结果
func (s *Service) VerifyOrSyncDomainDetail(ctx context.Context, domain, ip string) (*DomainVerifyResult, error) {
	domain = strings.TrimSpace(domain)
	ip = strings.TrimSpace(ip)
	if domain == "" || ip == "" {
		return nil, fmt.Errorf("domain and ip required")
	}

	res := &DomainVerifyResult{
		Domain:      domain,
		TargetIP:    ip,
		ResolvedIPs: []string{},
	}

	ips, err := net.LookupIP(domain)
	if err == nil {
		for _, resolved := range ips {
			ipStr := resolved.String()
			res.ResolvedIPs = append(res.ResolvedIPs, ipStr)
			if ipStr == ip {
				res.Matched = true
			}
			if isCloudflareProxyIP(ipStr) {
				res.IsCFProxy = true
			}
		}
	}

	if res.Matched {
		if res.IsCFProxy {
			res.StatusText = "警告：检测到该 IP 命中 Cloudflare CDN 代理网段，AERO 协议要求直连灰云 (DNS only)，请前往 CF 关闭代理"
		} else {
			res.StatusText = fmt.Sprintf("DNS 解析正常，直连灰云已生效 (%s)", ip)
		}
		return res, nil
	}

	// 2. 若不一致或尚未解析，检查是否启用 Cloudflare 自动同步
	if s.cf != nil && s.cf.Enabled() {
		_, cfErr := s.cf.SyncGrayCloudARecord(ctx, domain, ip)
		if cfErr == nil {
			res.CFSynced = true
			res.Matched = true
			res.StatusText = fmt.Sprintf("已通过 Cloudflare 自动同步灰云 A 记录 (%s -> %s)", domain, ip)
			return res, nil
		}
		return res, fmt.Errorf("域名 %s 解析 (%v) 与目标 IP (%s) 不一致，且 Cloudflare 自动同步失败: %w", domain, res.ResolvedIPs, ip, cfErr)
	}

	if err != nil {
		return res, fmt.Errorf("域名 %s 尚未在公网解析，且未配置 Cloudflare 自动解析服务，请先在 DNS 处添加 A 记录指向 %s", domain, ip)
	}
	return res, fmt.Errorf("域名 %s 当前解析出的 IP (%v) 与录入的 VPS IP (%s) 不一致，禁止接入", domain, res.ResolvedIPs, ip)
}


