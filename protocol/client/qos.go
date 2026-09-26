// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"net"
	"sync"
	"time"
)

// ISPProbeTarget 运营商测速目标
type ISPProbeTarget struct {
	Code string // "CT", "CU", "CM"
	Name string // "中国电信", "中国联通", "中国移动"
	Addr string // 目标 DNS / 骨干节点 IP:53
}

// DefaultISPProbeTargets 预设的各运营商骨干公共 DNS 探针
var DefaultISPProbeTargets = []ISPProbeTarget{
	{Code: "CT", Name: "中国电信", Addr: "218.2.135.1:53"},     // 电信骨干
	{Code: "CU", Name: "中国联通", Addr: "116.228.111.118:53"}, // 联通骨干
	{Code: "CM", Name: "中国移动", Addr: "211.136.192.6:53"},   // 移动骨干
}

// ISPProbeResult 运营商测速结果
type ISPProbeResult struct {
	BestISP string        // 胜出的最优运营商代码 (CT/CU/CM)
	BestRTT time.Duration // 最低 RTT
	AllRTTs map[string]time.Duration
	ProbeAt time.Time
}

// DetectISP 执行轻量 DNS RTT 测速，快速判定客户端所处网络运营商 (Rule: Thin Client)
func DetectISP(ctx context.Context, timeout time.Duration) *ISPProbeResult {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond // 800ms 快速探活，不拖慢启动
	}

	res := &ISPProbeResult{
		BestISP: "DEFAULT",
		BestRTT: 999 * time.Millisecond,
		AllRTTs: make(map[string]time.Duration),
		ProbeAt: time.Now(),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, target := range DefaultISPProbeTargets {
		t := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			rtt, err := probeTCPRTT(ctx, t.Addr, timeout)
			if err == nil && rtt > 0 {
				mu.Lock()
				res.AllRTTs[t.Code] = rtt
				if rtt < res.BestRTT {
					res.BestRTT = rtt
					res.BestISP = t.Code
				}
				mu.Unlock()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	case <-time.After(timeout):
	}

	return res
}

func probeTCPRTT(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	_ = conn.Close()
	return rtt, nil
}
