package public

import (
	"crypto/x509"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"github.com/aero-protocol/aero-ech/internal/h2pool"
	"github.com/aero-protocol/aero-ech/internal/tun"
	"github.com/aero-protocol/aero-ech/internal/transport"
)

// -----------------------------------------------------------------------------
// Source: transport.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");



// dialTCPH2 经 h2pool 复用 TLS+H2 会话，再对 target 发 CONNECT
func dialTCPH2(target string, preface []byte) (net.Conn, error) {
	if len(preface) > 0 {
		return h2pool.Default.OpenPreface(*edgeAddr, target, *token, dialEdgeTLS, preface)
	}
	return h2pool.Default.Open(*edgeAddr, target, *token, dialEdgeTLS)
}

// dialEdgeTLS 仅完成到 Edge 的 TCP+TLS（不含 H2）。
// 默认走标准 TLS1.3+h2（与 edge 兼容）。utls 指纹 + ClientHello 分片易被 edge 以
// "tls: internal error" 拒绝，导致「显示已连接但 SOCKS 全失败」。
func dialEdgeTLS() (net.Conn, error) {
	// 1) Prefer standard crypto/tls (reliable path to our edge)
	if *fingerprint == "" || *fingerprint == "std" || *fingerprint == "standard" {
		return dialEdgeTLSStd(false)
	}
	// 2) Optional utls fingerprint — without fragment first; fallback to std
	conn, err := dialEdgeTLSUTls(false)
	if err == nil {
		return conn, nil
	}
	log.Printf("[TLS] utls(%s) failed: %v — fallback std", *fingerprint, err)
	return dialEdgeTLSStd(false)
}

func dialEdgeTLSStd(useFragment bool) (net.Conn, error) {
	var tlsConfig *tls.Config
	if *echConfigB64 != "" {
		echData, err := base64.URLEncoding.DecodeString(*echConfigB64)
		if err == nil {
			cfg, err := transport.BuildClientConfigWithECH(transport.Config{
				PublicName:    *publicName,
				EnableRealECH: true,
				ECHPublicKey:  echData,
			})
			if err == nil {
				tlsConfig = cfg
			}
		}
	}
	if tlsConfig == nil {
		tlsConfig = transport.BuildClientConfig(*publicName)
	}
	// Ensure h2 ALPN for CONNECT path
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	if *echConfigB64 != "" && len(tlsConfig.EncryptedClientHelloConfigList) == 0 {
		if echRaw, _ := base64.URLEncoding.DecodeString(*echConfigB64); len(echRaw) > 0 {
			tlsConfig.EncryptedClientHelloConfigList = echRaw
			tlsConfig.ServerName = *publicName
		}
	}
	tcpConn, err := dialEdgeTCP(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	var raw net.Conn = tcpConn
	if useFragment {
		raw = transport.NewSplitter(tcpConn, 100, 10*time.Millisecond, 50*time.Millisecond)
	}
	tlsConn := tls.Client(raw, tlsConfig)
	if err := tlsConn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	tlsConn.SetDeadline(time.Time{})
	log.Printf("[TLS] std sni=%s alpn=%v", *publicName, tlsConn.ConnectionState().NegotiatedProtocol)
	return tlsConn, nil
}

func dialEdgeTLSUTls(useFragment bool) (net.Conn, error) {
	tcpConn, err := dialEdgeTCP(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	var raw net.Conn = tcpConn
	if useFragment {
		raw = transport.NewSplitter(tcpConn, 100, 10*time.Millisecond, 50*time.Millisecond)
	}
	utlsConfig := transport.BuildUTLSConfig(*publicName, *fingerprint)
	uconn, err := transport.NewUConn(raw, utlsConfig, *fingerprint)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("create uconn: %w", err)
	}
	if err := uconn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if err := uconn.HandshakeContext(); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}
	uconn.SetDeadline(time.Time{})
	log.Printf("[TLS] fingerprint=%s cipher=0x%x", *fingerprint, uconn.ConnectionState().CipherSuite)
	return uconn, nil
}

// dialEdgeTCP always leaves via the physical NIC. After TUN catch-all routes,
// a default Dial uses 10.88.0.2 and blackholes the edge (lookup/handshake timeout).
func dialEdgeTCP(timeout time.Duration) (net.Conn, error) {
	addr := *edgeAddr
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "443"
		addr = net.JoinHostPort(host, port)
	}
	if net.ParseIP(host) == nil {
		ip := tunEdgeIP
		if ip == "" {
			ip = lookupEdgeIPv4(host)
		}
		if ip != "" {
			addr = net.JoinHostPort(ip, port)
		}
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err == nil {
		return conn, nil
	}
	// Fallback: bind the NIC that currently owns 0.0.0.0/0 (never a stale WLAN IP).
	if lip := physicalIPv4(); lip != nil {
		d2 := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: lip}}
		c2, err2 := d2.DialContext(context.Background(), "tcp", addr)
		if err2 == nil {
			return c2, nil
		}
		return nil, fmt.Errorf("tcp dial: %v (bind %s: %v)", err, lip, err2)
	}
	return nil, err
}

func lookupEdgeIPv4(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func physicalIPv4() net.IP {
	if ip := tun.PhysicalIfaceIPv4(); ip != nil {
		return ip
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifaces {
		n := strings.ToLower(ifi.Name)
		if strings.Contains(n, "aero") || strings.Contains(n, "sing") || strings.Contains(n, "tun") || strings.Contains(n, "wintun") {
			continue
		}
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip[0] == 10 && ip[1] == 88 {
				continue
			}
			if ip[0] == 172 && ip[1] == 19 {
				continue
			}
			return ip
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Source: dial_transport.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");



// dialQUIC 建立 QUIC 连接并打开双向流
func dialQUIC(ctx context.Context, target string) (net.Conn, error) {
	_ = target
	cfg := transport.DefaultQUICConfig(*edgeAddr, *publicName)
	cfg.TLSConfig = transport.BuildClientConfig(*publicName)
	// 公网 ALPN 保持常见集合；私有协商放在 TLS 之后
	cfg.TLSConfig.NextProtos = []string{"h3"}

	client, err := transport.DialQUIC(ctx, cfg)
	if err != nil {
		return nil, err
	}

	stream, err := client.OpenStreamAsync(ctx)
	if err != nil {
		client.Close()
		return nil, err
	}

	return &quicConnWrapper{stream: stream, client: client}, nil
}

// quicConnWrapper 包装 QUIC 流为 net.Conn
type quicConnWrapper struct {
	stream    io.ReadWriteCloser
	client    *transport.QUICClient
	mu        sync.Mutex
	readTimer *time.Timer
	closed    bool
}

func (q *quicConnWrapper) Read(p []byte) (int, error)  { return q.stream.Read(p) }
func (q *quicConnWrapper) Write(p []byte) (int, error) { return q.stream.Write(p) }

func (q *quicConnWrapper) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	if q.readTimer != nil {
		q.readTimer.Stop()
		q.readTimer = nil
	}
	err1 := q.stream.Close()
	err2 := q.client.Close()
	if err2 != nil {
		return err2
	}
	return err1
}

func (q *quicConnWrapper) LocalAddr() net.Addr  { return q.client.LocalAddr() }
func (q *quicConnWrapper) RemoteAddr() net.Addr { return q.client.RemoteAddr() }

func (q *quicConnWrapper) SetDeadline(t time.Time) error {
	_ = q.SetWriteDeadline(t)
	return q.SetReadDeadline(t)
}

func (q *quicConnWrapper) SetReadDeadline(t time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.readTimer != nil {
		q.readTimer.Stop()
		q.readTimer = nil
	}
	if q.closed || t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		_ = q.stream.Close()
		return nil
	}
	q.readTimer = time.AfterFunc(d, func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if !q.closed {
			_ = q.stream.Close()
		}
	})
	return nil
}

func (q *quicConnWrapper) SetWriteDeadline(time.Time) error { return nil }

// -----------------------------------------------------------------------------
// Source: dial_select.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");



// preferQUIC 为 true 时才尝试 QUIC。默认 false：Edge QUIC 数据面未完成时优先 H2，避免半连接黑洞。
// 可通过环境变量 AERO_PREFER_QUIC=1 开启实验路径。
func preferQUIC() bool {
	v := os.Getenv("AERO_PREFER_QUIC")
	return v == "1" || v == "true"
}

// dialBestTransport 选择传输：默认 TCP+H2；仅 preferQUIC 且 UDP 可用时再试 QUIC。
// preface 非空时随 H2 CONNECT 体发出（与 200 重叠），调用方只再读 ConnectResponse。
func dialBestTransport(target string, preface []byte) (net.Conn, string, error) {
	if preferQUIC() && udpAvailable {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		quicConn, err := dialQUIC(ctx, target)
		if err == nil {
			log.Printf("[TRANSPORT] QUIC connected to %s (prefer_quic=1)", *edgeAddr)
			return quicConn, "quic", nil
		}
		log.Printf("[TRANSPORT] QUIC failed (%v), falling back to TCP H2", err)
	}

	tcpConn, err := dialTCPH2(target, preface)
	if err != nil {
		return nil, "", err
	}
	return tcpConn, "tcp_h2", nil
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
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
	OK      bool   `json:"ok"`
	MS      int64  `json:"ms"`
	Code    int    `json:"http_code,omitempty"`
	Target  string `json:"target"`
	Via     string `json:"via"`
	Error   string `json:"error,omitempty"`
	Detail  string `json:"detail,omitempty"`
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
	Pins:                  transport.Pins,
	HasPins:               transport.HasPins,
	MatchSPKI:             transport.MatchSPKI,
	VerifyPeerCertificate: transport.VerifyPeerCertificate,
}
