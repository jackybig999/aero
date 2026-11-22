// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DoH（C2，api/dataplane.md §6）：把客户端的 DNS 报文原样转发给宿主 /etc/resolv.conf 的上游并原样返回应答，
// 因此所有记录类型（A、AAAA、MX、TXT、SRV、HTTPS…）与应答码（NXDOMAIN 等）都保持不变。所有上游失败时返回
// SERVFAIL（不伪造“无记录”）。节点没有 IPv6 出口时 AAAA 返回空应答，让应用直接用 IPv4。不记录查询内容。

const (
	dohUpstreamTimeout = 2 * time.Second
	dohRatePerToken    = 50 // 每个 token 每秒查询数
	dohMaxLimiters     = 4096
	dnsTypeAAAA        = 28
)

// dohForwarder 转发 DNS 报文；upstreams 与 dial 可在测试中替换。
type dohForwarder struct {
	upstreams func() []string // host:port
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

func newDoHForwarder() *dohForwarder {
	d := &net.Dialer{}
	return &dohForwarder{upstreams: systemNameservers, dial: d.DialContext, limiters: make(map[string]*rate.Limiter)}
}

// systemNameservers 读取 /etc/resolv.conf 的 nameserver；没有时使用公共解析器。
func systemNameservers() []string {
	var out []string
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && fields[0] == "nameserver" {
				if ip := net.ParseIP(strings.Split(fields[1], "%")[0]); ip != nil {
					out = append(out, net.JoinHostPort(ip.String(), "53"))
				}
			}
		}
		_ = f.Close()
	}
	if len(out) == 0 {
		out = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return out
}

// allow 按 token 限流（每秒 50 次）。
func (f *dohForwarder) allow(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.limiters[token]
	if !ok {
		if len(f.limiters) >= dohMaxLimiters {
			for k := range f.limiters {
				delete(f.limiters, k)
				break
			}
		}
		l = rate.NewLimiter(dohRatePerToken, dohRatePerToken)
		f.limiters[token] = l
	}
	return l.Allow()
}

// exchange 依次尝试各上游：先 UDP，应答截断（TC）时改用 TCP。只接受与查询 ID 和问题段一致的应答。
func (f *dohForwarder) exchange(ctx context.Context, query []byte) ([]byte, error) {
	question, ok := dnsQuestionSection(query)
	if !ok {
		return nil, errors.New("malformed query")
	}
	var lastErr error
	for _, up := range f.upstreams() {
		resp, err := f.exchangeUDP(ctx, up, query, question)
		if err == nil && resp[2]&0x02 != 0 { // TC：改用 TCP 取完整应答
			resp, err = f.exchangeTCP(ctx, up, query, question)
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream")
	}
	return nil, lastErr
}

func (f *dohForwarder) exchangeUDP(ctx context.Context, up string, query, question []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dohUpstreamTimeout)
	defer cancel()
	c, err := f.dial(ctx, "udp", up)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if validDNSResponse(buf[:n], query, question) {
			return append([]byte(nil), buf[:n]...), nil
		}
		// ID 或问题段不符（迟到或伪造的应答）：丢弃，继续等待
	}
}

func (f *dohForwarder) exchangeTCP(ctx context.Context, up string, query, question []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dohUpstreamTimeout)
	defer cancel()
	c, err := f.dial(ctx, "tcp", up)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := c.Write(append(msg, query...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if !validDNSResponse(resp, query, question) {
		return nil, errors.New("mismatched TCP response")
	}
	return resp, nil
}

// dnsQuestionSection 返回查询的问题段原始字节（单个问题、未压缩名称），用于匹配应答。
func dnsQuestionSection(msg []byte) ([]byte, bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return nil, false
	}
	i := 12
	for {
		if i >= len(msg) {
			return nil, false
		}
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 || l > 63 {
			return nil, false
		}
		i += 1 + l
	}
	if i+4 > len(msg) {
		return nil, false
	}
	return msg[12 : i+4], true
}

// dnsQueryType 返回查询类型。
func dnsQueryType(msg []byte) (uint16, bool) {
	q, ok := dnsQuestionSection(msg)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(q[len(q)-4:]), true
}

func validDNSResponse(resp, query, question []byte) bool {
	return len(resp) >= 12+len(question) && resp[0] == query[0] && resp[1] == query[1] && resp[2]&0x80 != 0 &&
		bytes.Equal(resp[12:12+len(question)], question)
}

// dnsReply 由查询构造无记录的应答：只保留问题段，设置 QR、RA 与应答码（0 NOERROR，2 SERVFAIL）。
func dnsReply(query []byte, rcode byte) []byte {
	question, _ := dnsQuestionSection(query)
	out := make([]byte, 12, 12+len(question))
	copy(out, query[:4])
	out[2] = 0x80 | query[2]&0x79 // QR=1，保留 Opcode 与 RD，清除 AA/TC
	out[3] = 0x80 | rcode         // RA=1
	binary.BigEndian.PutUint16(out[4:6], 1)
	return append(out, question...)
}
