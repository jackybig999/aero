package service

import (
	"context"
	"sync"
	"time"

	"aisys/connect/os/internal/domain/proxy"
)

// StartProxyHealthPoller 启动后台代理健康定期轮询协程
func (s *AppService) StartProxyHealthPoller(interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	s.healthTicker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-s.healthTicker.C:
				s.CheckAllProxiesHealth()
			case <-s.healthStopChan:
				return
			}
		}
	}()
}

// CheckAllProxiesHealth 检查所有已保存代理的健康状态 (工作池并发模式)
func (s *AppService) CheckAllProxiesHealth() {
	rows, err := s.DB.Query(`SELECT id, raw_input, protocol, host, port, username, password FROM proxies`)
	if err != nil {
		return
	}

	type proxyItem struct {
		id  int64
		cfg *proxy.ProxyConfig
	}
	var items []proxyItem

	for rows.Next() {
		var id int64
		var raw, proto, host, user, pass string
		var port int
		if err := rows.Scan(&id, &raw, &proto, &host, &port, &user, &pass); err != nil {
			continue
		}
		items = append(items, proxyItem{
			id: id,
			cfg: &proxy.ProxyConfig{
				Enabled:  true,
				Protocol: proto,
				Host:     host,
				Port:     port,
				Username: user,
				Password: pass,
			},
		})
	}
	_ = rows.Close()

	if len(items) == 0 {
		return
	}

	maxWorkers := 8
	if len(items) < maxWorkers {
		maxWorkers = len(items)
	}
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, it := range items {
		wg.Add(1)
		go func(item proxyItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			info, _ := proxy.TestOutbound(ctx, item.cfg, 6*time.Second)
			cancel()

			if info != nil {
				s.mu.Lock()
				_, _ = s.DB.Exec(`UPDATE proxies SET outbound_ip = ?, latency_ms = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
					info.OutboundIP, info.LatencyMs, info.Status, item.id,
				)
				s.mu.Unlock()
			}
		}(it)
	}
	wg.Wait()
}

// StopHealthPoller 停止健康检测定时器
func (s *AppService) StopHealthPoller() {
	if s.healthTicker != nil {
		s.healthTicker.Stop()
		select {
		case <-s.healthStopChan:
		default:
			close(s.healthStopChan)
		}
	}
}
