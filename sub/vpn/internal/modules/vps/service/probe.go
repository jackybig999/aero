package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/sshprobe"
)

// Probe 采集单台 VPS 主机系统指标 (SSH)
func (s *Service) Probe(id uint64) (*domain.HostMetrics, error) {
	h, cipher, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	pass, err := s.box.Decrypt(cipher)
	if err != nil {
		m := &domain.HostMetrics{ProbeOK: false, ProbeError: "decrypt failed", Source: "none", CollectedAt: time.Now()}
		_ = s.store.UpdateMetrics(id, m, "error")
		return m, err
	}
	if pass == "" {
		m := &domain.HostMetrics{ProbeOK: false, ProbeError: "no password", Source: "none", CollectedAt: time.Now()}
		_ = s.store.UpdateMetrics(id, m, "error")
		return m, fmt.Errorf("no password stored for host %d", id)
	}
	client, err := sshprobe.Dial(sshprobe.Credentials{
		Host: h.IP, Port: h.SSHPort, User: h.SSHUsername, Password: pass,
	}, 5*time.Second)
	if err != nil {
		m := &domain.HostMetrics{
			ProbeOK: false, ProbeError: err.Error(), Source: "ssh",
			CollectedAt: time.Now(),
		}
		_ = s.store.UpdateMetrics(id, m, "error")
		return m, err
	}
	defer client.Close()

	met, err := sshprobe.CollectMetrics(client)
	if err != nil {
		m := &domain.HostMetrics{
			ProbeOK: false, ProbeError: err.Error(), Source: "ssh",
			CollectedAt: time.Now(),
		}
		_ = s.store.UpdateMetrics(id, m, "error")
		return m, err
	}
	if rx, tx, nerr := sshprobe.CollectNetDelta(client); nerr == nil {
		met.NetRxMbps = rx
		met.NetTxMbps = tx
	}
	met.ProbeOK = true
	met.CollectedAt = time.Now()
	status := "online"

	score, tier, state := CalculateCapacity(met)
	_ = s.store.UpdateCapacity(id, score, tier, state)
	_ = s.store.UpdateMetrics(id, met, status)
	return met, nil
}

// ProbeAll 并发探测全量 VPS 资产系统指标 (并发槽限制为 5)
func (s *Service) ProbeAll(ctx context.Context) ([]domain.VPSHost, error) {
	hosts, err := s.store.List()
	if err != nil {
		return nil, err
	}
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for _, h := range hosts {
		h := h
		if h.Status == "error" || h.IP == "" {
			continue
		}
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

// ProbePurity 在目标 VPS 本地通过 SSH 管道执行远程真实打靶，
// 严守探测真源：测目标 VPS 出口 IP，绝不测中台自身 IP。
func (s *Service) ProbePurity(ctx context.Context, id uint64) (*domain.PurityResult, error) {
	h, cipher, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}
	pass, err := s.box.Decrypt(cipher)
	if err != nil || pass == "" {
		return nil, fmt.Errorf("decrypt password failed for vps %d", id)
	}

	client, err := sshprobe.Dial(sshprobe.Credentials{
		Host: h.IP, Port: h.SSHPort, User: h.SSHUsername, Password: pass,
	}, 6*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh dial target vps: %w", err)
	}
	defer client.Close()

	// 目标 VPS 本地执行打靶指令 (4 秒超时)，单命令一次性取回
	cmd := `g_code=$(curl -s -m 4 -o /dev/null -w "%{http_code}" "https://www.google.com/search?q=aero_probe" 2>/dev/null || echo "000"); ` +
		`cf_code=$(curl -s -m 4 -o /dev/null -w "%{http_code}" "https://cloudflare.com/cdn-cgi/trace" 2>/dev/null || echo "000"); ` +
		`ai_code=$(curl -s -m 4 -o /dev/null -w "%{http_code}" "https://api.anthropic.com/api/hello" 2>/dev/null || echo "000"); ` +
		`warp_on=$(ip a 2>/dev/null | grep -q "warp" && echo "1" || echo "0"); ` +
		`echo "G:$g_code,CF:$cf_code,AI:$ai_code,WARP:$warp_on"`

	out, err := sshprobe.Run(client, cmd, 8*time.Second)
	res := &domain.PurityResult{
		VPSID:   id,
		ProbeAt: time.Now(),
	}
	if err != nil {
		res.ProbeError = err.Error()
		return res, err
	}
	res.RawOutput = strings.TrimSpace(out)

	// 解析打靶返回值: "G:200,CF:200,AI:404,WARP:0"
	parts := strings.Split(res.RawOutput, ",")
	gCode, cfCode, aiCode, warpOn := "000", "000", "000", "0"
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "G":
				gCode = kv[1]
			case "CF":
				cfCode = kv[1]
			case "AI":
				aiCode = kv[1]
			case "WARP":
				warpOn = kv[1]
			}
		}
	}

	// 1. 硬门禁判定：AI 接口遭遇 403 Forbidden、429 或阻断则一票否决
	if aiCode == "403" || aiCode == "429" || aiCode == "000" {
		res.AIBlocked = true
	} else {
		res.AIBlocked = false
	}

	// 2. 软评分计算：Google (60 分) + Cloudflare (40 分)
	if gCode == "200" {
		res.GoogleClean = true
		res.PurityScore += 60
	}
	if cfCode == "200" {
		res.CFClean = true
		res.PurityScore += 40
	}
	res.IsWARPEgress = (warpOn == "1")

	// 持久化落盘至 VPS 元数据
	_ = s.store.UpdatePurity(id, res.PurityScore, res.AIBlocked, res.GoogleClean, res.CFClean, res.IsWARPEgress)
	return res, nil
}

// ProbeAllPurity 并发对所有 VPS 节点执行纯净度远程打靶
func (s *Service) ProbeAllPurity(ctx context.Context) map[uint64]*domain.PurityResult {
	hosts, err := s.store.List()
	if err != nil {
		return nil
	}
	results := make(map[uint64]*domain.PurityResult)
	var mu sync.Mutex
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, h := range hosts {
		h := h
		if h.IP == "" || h.Status == "error" {
			continue
		}
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				if res, err := s.ProbePurity(ctx, id); err == nil && res != nil {
					mu.Lock()
					results[id] = res
					mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}(h.ID)
	}
	wg.Wait()
	return results
}

// StartPurityTicker 固化调度时钟：后台 Ticker 默认每 4 小时例行打靶一次
func (s *Service) StartPurityTicker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 4 * time.Hour
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Printf("[VPS-PURITY] starting scheduled 4h purity probe cycle...")
				_ = s.ProbeAllPurity(ctx)
			}
		}
	}()
}
