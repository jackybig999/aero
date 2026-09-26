package public

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/aero-protocol/aero-ech/internal/transport"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// -----------------------------------------------------------------------------
// Source: transport.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// WhiteSNIPool 常用顶级免流/防封白名单 SNI 候选池
var WhiteSNIPool = []string{
	"gateway.icloud.com",
	"swdist.apple.com",
	"edge.microsoft.com",
	"live.azure.com",
}

func currentEdgeSNI() string {
	sni := ""
	if publicName != nil {
		sni = strings.TrimSpace(*publicName)
	}
	// 当显式开启白名单或自动伪装模式且已加载 SPKI 钉扎时，自动借用顶级白名单伪装
	if (sni == "white" || sni == "auto") && len(transport.Pins()) > 0 {
		return WhiteSNIPool[0]
	}
	if (sni == "" || sni == "cdn-aero.com" || sni == "auto" || sni == "white") && edgeAddr != nil && *edgeAddr != "" {
		host, _, err := net.SplitHostPort(*edgeAddr)
		if err == nil && net.ParseIP(host) == nil && host != "" {
			sni = host
		}
	}
	if sni == "" || sni == "auto" || sni == "white" || sni == "cdn-aero.com" {
		sni = "edge.microsoft.com"
	}
	return sni
}

// dialQUIC 建立 QUIC 连接并打开双向流（复用全局持久 SessionPool）
func dialQUIC(ctx context.Context, target string) (net.Conn, error) {
	_ = target
	cfg := transport.DefaultQUICConfig(*edgeAddr, *publicName)
	cfg.TLSConfig = transport.BuildClientConfig(*publicName)
	cfg.TLSConfig.NextProtos = []string{"h3"}

	client, err := transport.GlobalSessionPool.Get(ctx, cfg)
	if err != nil {
		return nil, err
	}

	stream, err := client.OpenStreamAsync(ctx)
	if err != nil {
		transport.GlobalSessionPool.Remove(*edgeAddr)
		return nil, err
	}

	return &quicConnWrapper{stream: stream, client: client}, nil
}

// quicConnWrapper 包装 QUIC 流为 net.Conn
type quicConnWrapper struct {
	stream io.ReadWriteCloser
	client *transport.QUICClient
	closed atomic.Bool
}

func (q *quicConnWrapper) Read(p []byte) (int, error)  { return q.stream.Read(p) }
func (q *quicConnWrapper) Write(p []byte) (int, error) { return q.stream.Write(p) }

func (q *quicConnWrapper) Close() error {
	if q.closed.Swap(true) {
		return nil
	}
	// 契约设计：仅关闭当前 Stream，绝对不关闭底层复用的持久 QUIC Client 会话！
	return q.stream.Close()
}

func (q *quicConnWrapper) LocalAddr() net.Addr  { return q.client.LocalAddr() }
func (q *quicConnWrapper) RemoteAddr() net.Addr { return q.client.RemoteAddr() }

func (q *quicConnWrapper) SetDeadline(t time.Time) error {
	if s, ok := q.stream.(interface{ SetDeadline(time.Time) error }); ok {
		return s.SetDeadline(t)
	}
	return nil
}

func (q *quicConnWrapper) SetReadDeadline(t time.Time) error {
	if s, ok := q.stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return s.SetReadDeadline(t)
	}
	return nil
}

func (q *quicConnWrapper) SetWriteDeadline(t time.Time) error {
	if s, ok := q.stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return s.SetWriteDeadline(t)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Source: dial_select.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// dialBestTransport 纯正 HTTP/3 (QUIC) 传输通道，严禁任何向老旧 TCP H2 的降级。
func dialBestTransport(target string, preface []byte) (net.Conn, string, error) {
	_ = preface
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	quicConn, err := dialQUIC(ctx, target)
	if err != nil {
		return nil, "", fmt.Errorf("http3 dial %s: %w", *edgeAddr, err)
	}
	return quicConn, "quic", nil
}

// -----------------------------------------------------------------------------
// Source: direct.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

func handleDirect(client net.Conn, target string, ready replyFn) {
	if ready == nil {
		ready = func(bool) {}
	}

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		if ipTarget, rerr := resolveViaPublicDNS(target); rerr == nil {
			conn, err = net.DialTimeout("tcp", ipTarget, 10*time.Second)
		}
	}
	if err != nil {
		log.Printf("[DIRECT] dial %s failed: %v", target, err)
		ready(false)
		return
	}
	defer conn.Close()

	ready(true)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, client)
		_ = conn.SetDeadline(time.Now())
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, conn)
		_ = client.SetDeadline(time.Now())
		done <- struct{}{}
	}()
	<-done
	_ = conn.SetDeadline(time.Now())
	_ = client.SetDeadline(time.Now())
	<-done
}

func resolveViaPublicDNS(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	if net.ParseIP(host) != nil {
		return target, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1 * time.Second}
			return d.DialContext(ctx, "udp", "223.5.5.5:53")
		},
	}
	ips, err := r.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return "", err
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// -----------------------------------------------------------------------------
// Source: probe.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// ProbeResult is a live path check through the local mixed proxy (not just "engine up").
type ProbeResult struct {
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms"`
	Code   int    `json:"http_code,omitempty"`
	Target string `json:"target"`
	Via    string `json:"via"`
	Error  string `json:"error,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// probeThroughLocalProxy GETs a lightweight URL via local HTTP CONNECT proxy.
// This is what "真正能上网" means — UI must not show green without this.
func probeThroughLocalProxy(listen string) ProbeResult {
	if listen == "" {
		listen = "127.0.0.1:55555"
	}
	target := "https://www.google.com/generate_204"
	res := ProbeResult{Target: target, Via: "http://" + listen}
	start := time.Now()

	// Use mixed port as HTTP proxy (CONNECT for HTTPS)
	tr := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL("http://" + listen)),
		DialContext: (&net.Dialer{
			Timeout: 8 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		// edge may be self-signed; probe is about tunnel data path not leaf trust of google
		// google cert is validated by system roots through tunnel
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   25 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		res.Error = err.Error()
		res.MS = time.Since(start).Milliseconds()
		return res
	}
	resp, err := client.Do(req)
	res.MS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.Detail = "隧道探测失败：本地代理或 Edge 未真正转发"
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	res.Code = resp.StatusCode
	// generate_204 → 204; some regions 200/302 still mean path works
	if resp.StatusCode > 0 && resp.StatusCode < 500 {
		res.OK = true
		res.Detail = fmt.Sprintf("出站 OK HTTP %d via %s", resp.StatusCode, listen)
	} else {
		res.Detail = fmt.Sprintf("出站异常 HTTP %d", resp.StatusCode)
		res.Error = res.Detail
	}
	return res
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return &url.URL{Scheme: "http", Host: "127.0.0.1:55555"}
	}
	return u
}

// probeUDP best-effort check whether UDP toward edge host is usable.
func probeUDP(host string, preferredPort int) bool {
	if host == "" {
		return false
	}
	port := preferredPort
	if port <= 0 {
		port = 443
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	c, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// -----------------------------------------------------------------------------
// Source: nonce.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// generateNonce 生成 32 字节随机 nonce，用于 ConnectRequest 防重放
func generateNonce() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// 熵耗尽时回退到时间戳填充
		ts := time.Now().UnixNano()
		for i := 0; i < 8 && i < len(b); i++ {
			b[i] = byte(ts >> (i * 8))
		}
	}
	return b
}

// certloader compatibility wrapper
var certloader = struct {
	SetGlobal             func(*x509.CertPool)
	LoadCA                func(string) (*x509.CertPool, error)
	RootCAs               func() *x509.CertPool
	SetInsecure           func(bool)
	InsecureAllowed       func() bool
	ShouldSkipVerify      func() bool
	SetPins               func([]string)
	AddPins               func([]string)
	ClearPins             func()
	Pins                  func() []string
	HasPins               func() bool
	MatchSPKI             func(*x509.Certificate) bool
	VerifyPeerCertificate func([][]byte, [][]*x509.Certificate) error
}{
	SetGlobal:             transport.SetGlobal,
	LoadCA:                transport.LoadCA,
	RootCAs:               transport.RootCAs,
	SetInsecure:           transport.SetInsecure,
	InsecureAllowed:       transport.InsecureAllowed,
	ShouldSkipVerify:      transport.ShouldSkipVerify,
	SetPins:               transport.SetPins,
	AddPins:               func(pins []string) { transport.AddPins(pins...) },
	ClearPins:             transport.ClearPins,
	Pins:                  transport.Pins,
	HasPins:               transport.HasPins,
	MatchSPKI:             transport.MatchSPKI,
	VerifyPeerCertificate: transport.VerifyPeerCertificate,
}
