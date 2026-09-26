// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edgepool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ProbePath 表示一条探测路径
type ProbePath struct {
	Protocol string // "tcp"
	Port     int
	Addr     string // host:port
}

// ProbeResult 探测结果
type ProbeResult struct {
	Path      ProbePath
	RTT       time.Duration
	Reachable bool
	Error     error
}

// ProbeConfig 探测配置
type ProbeConfig struct {
	Host    string
	Timeout time.Duration
	Paths   []ProbePath
}

// DefaultProbePaths 默认探测路径（按优先级排序）
var DefaultProbePaths = []ProbePath{
	{Protocol: "quic", Port: 443},
	{Protocol: "quic", Port: 8443},
	{Protocol: "tcp", Port: 443},
	{Protocol: "tcp", Port: 8443},
	{Protocol: "tcp", Port: 80},
}

// Probe 并行探测所有路径，返回结果列表
type Probe struct {
	config ProbeConfig
}

// NewProbe 创建探测器
func NewProbe(host string) *Probe {
	return NewProbeWithPreferredPort(host, 0)
}

// NewProbeWithPreferredPort 创建探测器，支持优先端口
func NewProbeWithPreferredPort(host string, preferredPort int) *Probe {
	paths := make([]ProbePath, 0, len(DefaultProbePaths)+2)
	if preferredPort > 0 {
		paths = append(paths,
			ProbePath{Protocol: "quic", Port: preferredPort, Addr: net.JoinHostPort(host, strconv.Itoa(preferredPort))},
			ProbePath{Protocol: "tcp", Port: preferredPort, Addr: net.JoinHostPort(host, strconv.Itoa(preferredPort))},
		)
	}
	for _, p := range DefaultProbePaths {
		if preferredPort > 0 && p.Port == preferredPort {
			continue
		}
		p.Addr = net.JoinHostPort(host, strconv.Itoa(p.Port))
		paths = append(paths, p)
	}

	return &Probe{
		config: ProbeConfig{
			Host:    host,
			Timeout: 3 * time.Second,
			Paths:   paths,
		},
	}
}

// Run 执行探测（兼容方法）
func (p *Probe) Run() []ProbeResult {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()
	return p.ProbeAll(ctx)
}

// ProbeAll 并行探测所有路径
func (p *Probe) ProbeAll(ctx context.Context) []ProbeResult {
	results := make([]ProbeResult, len(p.config.Paths))
	var wg sync.WaitGroup

	for i, path := range p.config.Paths {
		wg.Add(1)
		go func(idx int, target ProbePath) {
			defer wg.Done()
			results[idx] = p.probeOne(ctx, target)
		}(i, path)
	}

	wg.Wait()
	return results
}

// BestProbe 返回 RTT 最低的可用路径
func (p *Probe) BestProbe(ctx context.Context) *ProbeResult {
	results := p.ProbeAll(ctx)
	var best *ProbeResult

	for i := range results {
		r := &results[i]
		if !r.Reachable {
			continue
		}
		if best == nil || r.RTT < best.RTT {
			best = r
		}
	}

	return best
}

func (p *Probe) probeOne(ctx context.Context, path ProbePath) ProbeResult {
	probeCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	start := time.Now()
	var err error

	switch path.Protocol {
	case "tcp":
		err = p.probeTCP(probeCtx, path.Addr)
	case "quic":
		err = p.probeQUIC(probeCtx, path.Addr)
	default:
		err = fmt.Errorf("unknown protocol: %s", path.Protocol)
	}

	rtt := time.Since(start)

	return ProbeResult{
		Path:      path,
		RTT:       rtt,
		Reachable: err == nil,
		Error:     err,
	}
}

func (p *Probe) probeTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	return tlsConn.HandshakeContext(ctx)
}

func (p *Probe) probeQUIC(ctx context.Context, addr string) error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "aero/1.0"},
	}
	quicConf := &quic.Config{
		HandshakeIdleTimeout: 3 * time.Second,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	return nil
}

// QuickProbeTCP 快速 TCP 探活
func QuickProbeTCP(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// QuickProbeQUIC 快速 QUIC 探活
func QuickProbeQUIC(addr string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	quicConf := &quic.Config{
		HandshakeIdleTimeout: timeout,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return false
	}
	conn.CloseWithError(0, "")
	return true
}

// FormatProbeReport 格式化探测报告
func FormatProbeReport(results []ProbeResult) string {
	var s strings.Builder
	s.WriteString("Probe Results:\n")
	for _, r := range results {
		status := "OK"
		if !r.Reachable {
			status = fmt.Sprintf("FAIL (%v)", r.Error)
		}
		s.WriteString(fmt.Sprintf("  [%s] %s: RTT=%v %s\n",
			r.Path.Protocol, r.Path.Addr, r.RTT, status))
	}
	return s.String()
}
