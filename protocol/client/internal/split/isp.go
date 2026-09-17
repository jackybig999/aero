// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package split

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ISPType 运营商类型
type ISPType int

const (
	ISPUnknown ISPType = iota
	ChinaTelecom
	ChinaUnicom
	ChinaMobile
	ChinaBroadcast
)

func (t ISPType) String() string {
	switch t {
	case ChinaTelecom:
		return "china_telecom"
	case ChinaUnicom:
		return "china_unicom"
	case ChinaMobile:
		return "china_mobile"
	case ChinaBroadcast:
		return "china_broadcast"
	default:
		return "unknown"
	}
}

// ISPDNSServer 运营商 DNS 探测点
type ISPDNSServer struct {
	ISP  ISPType
	Addr string
	Name string
}

// DefaultISPDNSServers 默认 DNS 探测列表
var DefaultISPDNSServers = []ISPDNSServer{
	{ChinaTelecom, "202.96.128.86:53", "电信上海"},
	{ChinaTelecom, "202.96.134.33:53", "电信广东"},
	{ChinaTelecom, "114.114.114.114:53", "电信全国"},
	{ChinaUnicom, "202.106.0.20:53", "联通北京"},
	{ChinaUnicom, "202.106.196.115:53", "联通上海"},
	{ChinaUnicom, "123.125.81.6:53", "联通全国"},
	{ChinaMobile, "211.136.112.50:53", "移动上海"},
	{ChinaMobile, "211.136.150.66:53", "移动广东"},
	{ChinaMobile, "223.5.5.5:53", "移动阿里"},
}

// ISPResult 探测结果
type ISPResult struct {
	ISP       ISPType
	Server    ISPDNSServer
	RTT       time.Duration
	Reachable bool
	Error     error
}

// ISPDetector 运营商探测器
type ISPDetector struct {
	timeout time.Duration
	servers []ISPDNSServer
}

// NewISPDetector 创建探测器
func NewISPDetector() *ISPDetector {
	return &ISPDetector{
		timeout: 2 * time.Second,
		servers: DefaultISPDNSServers,
	}
}

// SetTimeout 设置探测超时
func (d *ISPDetector) SetTimeout(t time.Duration) {
	d.timeout = t
}

// Detect 执行运营商识别，返回最可能的运营商和探测详情
func (d *ISPDetector) Detect() (ISPType, []ISPResult) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	results := make([]ISPResult, len(d.servers))
	var wg sync.WaitGroup

	for i, srv := range d.servers {
		wg.Add(1)
		go func(idx int, s ISPDNSServer) {
			defer wg.Done()
			results[idx] = d.probeOne(ctx, s)
		}(i, srv)
	}

	wg.Wait()

	// 按运营商聚合 RTT
	rttByISP := make(map[ISPType][]time.Duration)
	for _, r := range results {
		if r.Reachable {
			rttByISP[r.ISP] = append(rttByISP[r.ISP], r.RTT)
		}
	}

	// 计算每个运营商的平均 RTT，选择最低的
	var bestISP ISPType = ISPUnknown
	var bestRTT time.Duration = -1

	for isp, rtts := range rttByISP {
		if len(rtts) == 0 {
			continue
		}
		var sum time.Duration
		for _, rtt := range rtts {
			sum += rtt
		}
		avg := sum / time.Duration(len(rtts))
		if bestRTT < 0 || avg < bestRTT {
			bestRTT = avg
			bestISP = isp
		}
	}

	return bestISP, results
}

func (d *ISPDetector) probeOne(ctx context.Context, srv ISPDNSServer) ISPResult {
	start := time.Now()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			dd := net.Dialer{Timeout: d.timeout}
			return dd.DialContext(dialCtx, "udp", srv.Addr)
		},
	}

	_, err := resolver.LookupHost(ctx, "aero-protocol.com")
	rtt := time.Since(start)

	if err != nil {
		return ISPResult{
			ISP:       srv.ISP,
			Server:    srv,
			RTT:       0,
			Reachable: false,
			Error:     err,
		}
	}

	return ISPResult{
		ISP:       srv.ISP,
		Server:    srv,
		RTT:       rtt,
		Reachable: true,
	}
}

// ISPReport 格式化探测报告
func ISPReport(ispType ISPType, results []ISPResult) string {
	var s string
	s += fmt.Sprintf("ISP Detection: %s\n", ispType.String())
	for _, r := range results {
		if r.Reachable {
			s += fmt.Sprintf("  %s (%s): RTT=%v\n", r.ISP.String(), r.Server.Name, r.RTT)
		} else {
			s += fmt.Sprintf("  %s (%s): FAIL\n", r.ISP.String(), r.Server.Name)
		}
	}
	return s
}
