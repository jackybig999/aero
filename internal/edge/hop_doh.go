package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// hopDoHTimeout 是入口等待出口 DoH 应答的上限（出口自身对上游还有超时）。
const hopDoHTimeout = 8 * time.Second

// hopDoHMaxResponse 是出口 DoH 应答的读取上限（DNS over TCP 报文最大 65535 字节）。
const hopDoHMaxResponse = 65535

// hopDoHClient 持有到出口的复用连接：http3.Transport 按目标地址保持一条 QUIC 连接，
// 并发查询共用它，不会每个请求重新握手。
type hopDoHClient struct {
	mu     sync.Mutex
	closed bool // Close 之后不再新建 Transport，避免关闭期间的转发请求泄漏连接
	client *http.Client
	tr     *http3.Transport
}

// nextHopSNI 返回校验出口证书使用的服务器名：优先 next_hop_sni，否则取 next_hop_addr 的主机部分。
func nextHopSNI(cfg *ServerConfig) string {
	if cfg == nil {
		return ""
	}
	return dialSNI(cfg, cfg.NextHopAddr)
}

// dialSNI 返回拨号 addr 时校验证书的服务器名：配置了 next_hop_sni 就用它，否则取 addr 的主机部分。
func dialSNI(cfg *ServerConfig, addr string) string {
	if cfg != nil && cfg.NextHopSNI != "" {
		return cfg.NextHopSNI
	}
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		return host
	}
	return addr
}

func (s *QUICServer) hopDoH() (*http.Client, error) {
	s.hopDoHc.mu.Lock()
	defer s.hopDoHc.mu.Unlock()
	if s.hopDoHc.closed {
		return nil, errors.New("server closed")
	}
	if s.hopDoHc.client == nil {
		tr := &http3.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         nextHopSNI(s.cfg),
				InsecureSkipVerify: s.allowLoopbackForTest.Load(),
				NextProtos:         []string{"h3"},
			},
			QUICConfig: DefaultQUICConfig(),
		}
		s.hopDoHc.tr = tr
		s.hopDoHc.client = &http.Client{
			Transport: tr,
			Timeout:   hopDoHTimeout,
			// 出口不应重定向；遇到重定向当作失败，避免把跳间凭证带到别处。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return s.hopDoHc.client, nil
}

// closeHopDoH 关闭到出口的复用连接（QUICServer.Close 调用）。
func (s *QUICServer) closeHopDoH() {
	s.hopDoHc.mu.Lock()
	defer s.hopDoHc.mu.Unlock()
	s.hopDoHc.closed = true
	if s.hopDoHc.tr != nil {
		_ = s.hopDoHc.tr.Close()
		s.hopDoHc.tr = nil
	}
}

// forwardDoHToNextHop 把已校验的 DoH 查询原样转给出口，返回出口的原始应答。
// 只接受状态 200、Content-Type 为 application/dns-message、事务 ID 一致的应答；
// 其余一律返回错误，由调用方回 SERVFAIL（入口不自行解析，避免从入口出网）。
func (s *QUICServer) forwardDoHToNextHop(ctx context.Context, query []byte) ([]byte, error) {
	if s.cfg == nil || strings.TrimSpace(s.cfg.NextHopAddr) == "" {
		return nil, errors.New("next hop address not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+s.cfg.NextHopAddr+"/dns-query", bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("build next hop doh request: %w", err)
	}
	req.Host = nextHopSNI(s.cfg)
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Aero-Hop-Token", s.cfg.HopCredential)

	client, err := s.hopDoH()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("next hop doh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("next hop doh status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		return nil, fmt.Errorf("next hop doh content-type %q", ct)
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, hopDoHMaxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read next hop doh response: %w", err)
	}
	if len(out) < 12 || len(out) > hopDoHMaxResponse {
		return nil, fmt.Errorf("next hop doh response length %d", len(out))
	}
	if out[0] != query[0] || out[1] != query[1] {
		return nil, errors.New("next hop doh response id mismatch")
	}
	return out, nil
}
