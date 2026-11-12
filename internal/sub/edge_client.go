package sub

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// 中台调用 edge 接口的唯一出口（组件只通过接口连接）。
// 节点使用真实域名 + Let's Encrypt 证书：一律按域名严格校验证书，密钥只放 Authorization 头，
// 不放 URL（会进入日志）。域名解析失败时可按 IP 直连，但 SNI 与证书校验仍用域名；没有域名的节点
// 无法校验身份，不发送密钥。

// edgeTLSConfig 可由测试替换（信任测试证书）；生产使用系统根证书。
var edgeTLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}

// edgeDial 可由测试替换（避免真实 DNS）。
var edgeDial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
}

var errEdgeNoDomain = errors.New("node has no domain; refusing to send credentials to an unverifiable peer")

// edgeDo 以 key 调用 edge 的 path，依次尝试域名与 IP；返回第一个建立连接的响应（调用方关闭 Body）。
func edgeDo(ctx context.Context, host, ip string, port int, method, path, key string, body []byte, timeout time.Duration) (*http.Response, error) {
	if host == "" || net.ParseIP(host) != nil {
		return nil, errEdgeNoDomain
	}
	if port <= 0 {
		port = 443
	}
	tlsCfg := edgeTLSConfig.Clone()
	tlsCfg.ServerName = host
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return edgeDial(ctx, network, addr, timeout)
			},
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	targets := []string{host}
	if ip != "" && ip != host {
		targets = append(targets, ip)
	}
	var lastErr error
	for _, tgt := range targets {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, "https://"+net.JoinHostPort(tgt, strconv.Itoa(port))+path, rd)
		if err != nil {
			return nil, err
		}
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("User-Agent", "AERO-Sub/1.0")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = fmt.Errorf("%s: %w", tgt, err)
	}
	return nil, lastErr
}
