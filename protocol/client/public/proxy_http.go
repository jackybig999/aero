package public

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/aero-protocol/aero-ech/internal/split"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// Source: httpproxy.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// handleHTTPProxyBuffered: HTTP/HTTPS proxy (CONNECT + absolute-form) after mixed peek.
func handleHTTPProxyBuffered(client net.Conn, br *bufio.Reader, unwrapDepth int) {
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("[HTTP-PROXY] read request: %v", err)
		return
	}

	bc := &bufConn{Conn: client, r: br}

	if req.Method == http.MethodConnect {
		target := req.Host
		if target == "" {
			writeHTTPStatus(client, 400, "missing host")
			return
		}
		if !strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "443")
		}
		if isSelfListenTarget(target) {
			// Roxy roxynet (and similar) chains the Windows system proxy in
			// front of the SOCKS5 the user typed. With sysproxy = 55555 and
			// target = socks5://127.0.0.1:55555 it HTTP-CONNECTs to us, then
			// speaks SOCKS5 on the tunnel. 403 here is why 55555 failed in
			// Roxy while box 12080 (different port) succeeded.
			if unwrapDepth >= 1 {
				writeHTTPStatus(client, 403, "self loop forbidden")
				return
			}
			log.Printf("[HTTP-PROXY] CONNECT self-unwrap %s", target)
			if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return
			}
			dispatchMixed(client, br, unwrapDepth+1)
			return
		}
		viaProxy := splitEngine == nil || splitEngine.MatchDomain(target) != split.DIRECT
		if viaProxy {
			log.Printf("[HTTP-PROXY] CONNECT %s", target)
		}
		serveTarget(bc, target, func(ok bool) {
			if ok {
				if viaProxy {
					log.Printf("[HTTP-PROXY] CONNECT ok %s", target)
				}
				if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					_ = client.Close()
					return
				}
			} else {
				log.Printf("[HTTP-PROXY] CONNECT fail %s", target)
				writeHTTPStatus(client, 502, "tunnel failed")
				_ = client.Close()
			}
		})
		return
	}

	// Absolute-form: GET http://host/path HTTP/1.1  (plain HTTP via proxy)
	target, err := absoluteProxyTarget(req)
	if err != nil {
		// origin-form without host often means probe of the proxy itself
		if req.URL != nil && (req.URL.Host == "" || req.Host == "" || isSelfListenTarget(req.Host)) {
			writeHTTPStatus(client, 200, "OK")
			return
		}
		writeHTTPStatus(client, 400, err.Error())
		return
	}
	// Apps health-check the proxy: HEAD/GET http://127.0.0.1:55555/ — answer 200, never re-dial self.
	if isSelfListenTarget(target) {
		writeHTTPStatus(client, 200, "OK")
		return
	}
	// Windows NCSI: if this fails, the OS marks "No Internet" and browsers
	// behave as if offline. Answer locally — do not DIRECT-dial IPv6 NCSI.
	if isWindowsNCSIHost(target) {
		log.Printf("[HTTP-PROXY] NCSI local %s %s", req.Method, target)
		writeNCSIReply(client)
		return
	}
	// GET/POST https://host/... is not CONNECT. Sending plaintext HTTP to :443
	// corrupts the origin TLS listener. Speak TLS ourselves through the tunnel.
	if req.URL != nil && strings.EqualFold(req.URL.Scheme, "https") {
		log.Printf("[HTTP-PROXY] HTTPS %s %s", req.Method, target)
		handleHTTPSAbsolute(bc, br, req, target)
		return
	}
	log.Printf("[HTTP-PROXY] %s %s -> %s", req.Method, req.URL.String(), target)

	originReq, err := rewriteOriginRequest(req)
	if err != nil {
		writeHTTPStatus(client, 400, err.Error())
		return
	}
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if err := originReq.Write(pw); err != nil {
			return
		}
		_, _ = io.Copy(pw, br)
	}()
	hc := &httpProxyConn{r: pr, w: client, raw: client}
	serveTarget(hc, target, func(ok bool) {
		if !ok {
			writeHTTPStatus(client, 502, "tunnel failed")
		}
	})
}

func absoluteProxyTarget(req *http.Request) (string, error) {
	if req.URL == nil {
		return "", fmt.Errorf("missing url")
	}
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		return "", fmt.Errorf("missing host")
	}
	if !strings.Contains(host, ":") {
		if req.URL.Scheme == "https" {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}
	return host, nil
}

func rewriteOriginRequest(req *http.Request) (*http.Request, error) {
	u := req.URL
	if u == nil {
		return nil, fmt.Errorf("missing url")
	}
	out := req.Clone(req.Context())
	out.RequestURI = ""
	path := u.Path
	if path == "" {
		path = "/"
	}
	out.URL = &url.URL{Path: path, RawQuery: u.RawQuery, Fragment: u.Fragment}
	if out.Host == "" {
		out.Host = u.Host
	}
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	return out, nil
}

func handleHTTPSAbsolute(client net.Conn, br *bufio.Reader, req *http.Request, target string) {
	originReq, err := rewriteOriginRequest(req)
	if err != nil {
		writeHTTPStatus(client, 400, err.Error())
		return
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	var raw net.Conn
	if splitEngine != nil && splitEngine.MatchDomain(target) == split.DIRECT {
		raw, err = net.DialTimeout("tcp", target, 12*time.Second)
	} else {
		raw, err = openAEROStream(target)
	}
	if err != nil {
		log.Printf("[HTTP-PROXY] HTTPS dial %s: %v", target, err)
		writeHTTPStatus(client, 502, "tunnel failed")
		return
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		log.Printf("[HTTP-PROXY] HTTPS handshake %s: %v", target, err)
		writeHTTPStatus(client, 502, "tls failed")
		return
	}
	defer tlsConn.Close()
	if err := originReq.Write(tlsConn); err != nil {
		writeHTTPStatus(client, 502, "write failed")
		return
	}
	_, _ = io.Copy(tlsConn, io.LimitReader(br, 1<<20))
	_, _ = io.Copy(client, tlsConn)
}

func isWindowsNCSIHost(target string) bool {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return strings.Contains(host, "msftconnecttest.com") || strings.Contains(host, "msftncsi.com")
}

func writeNCSIReply(w io.Writer) {
	const body = "Microsoft Connect Test"
	_, _ = fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func writeHTTPStatus(w io.Writer, code int, msg string) {
	if msg == "" {
		msg = http.StatusText(code)
	}
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", code, msg)
}

// bufConn prioritizes buffered bytes then the underlying conn.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *bufConn) Unwrap() net.Conn {
	return c.Conn
}

// httpProxyConn: request stream from pipe reader, responses to real client.
type httpProxyConn struct {
	r   io.Reader
	w   io.Writer
	raw net.Conn
}

func (c *httpProxyConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *httpProxyConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *httpProxyConn) Close() error                       { return c.raw.Close() }
func (c *httpProxyConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *httpProxyConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *httpProxyConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *httpProxyConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *httpProxyConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// -----------------------------------------------------------------------------
// Source: mixed.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// handleMixedClient is a Clash/sing-box style mixed inbound on ONE port:
//   - first byte 0x05  → SOCKS5
//   - first byte ASCII → HTTP proxy (GET/POST/CONNECT/…; HTTPS uses CONNECT)
//
// Same address is advertised as both HTTP and SOCKS5 (e.g. 127.0.0.1:55555).
func handleMixedClient(client net.Conn) {
	defer client.Close()
	dispatchMixed(client, bufio.NewReader(client), 0)
}

// dispatchMixed classifies one inbound protocol on an already-buffered conn.
// unwrapDepth limits HTTP CONNECT-to-self (Roxy roxynet chains
// socks5://127.0.0.1:55555 through system HTTP 127.0.0.1:55555).
func dispatchMixed(client net.Conn, br *bufio.Reader, unwrapDepth int) {
	head, err := br.Peek(1)
	if err != nil {
		return
	}

	switch {
	case head[0] == 0x05:
		handleSocks5Buffered(client, br)
	case isHTTPProxyByte(head[0]):
		handleHTTPProxyBuffered(client, br, unwrapDepth)
	case head[0] == 0x04:
		handleSocks4Buffered(client, br)
	case head[0] == 0x16:
		log.Printf("[MIXED] TLS/HTTPS-proxy to mixed port from %s — use HTTP or SOCKS5, not HTTPS proxy", client.RemoteAddr())
	default:
		log.Printf("[MIXED] unknown protocol 0x%02x from %s", head[0], client.RemoteAddr())
	}
}

func isHTTPProxyByte(b byte) bool {
	// HTTP methods start with letter; CONNECT/GET/POST/PUT/HEAD/OPTIONS/DELETE/PATCH
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// -----------------------------------------------------------------------------
// Source: mixed_listen.go
// -----------------------------------------------------------------------------
var (
	mixedMu sync.Mutex
	mixedLn net.Listener
)

func startMixedListen() error {
	mixedMu.Lock()
	defer mixedMu.Unlock()
	if mixedLn != nil {
		return nil
	}
	addr := "127.0.0.1:55555"
	if listenAddr != nil && *listenAddr != "" {
		addr = *listenAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mixedLn = ln
	go acceptMixed(ln)
	log.Printf("[MIXED] listen %s", addr)
	return nil
}

func stopMixedListen() {
	mixedMu.Lock()
	ln := mixedLn
	mixedLn = nil
	mixedMu.Unlock()
	if ln != nil {
		_ = ln.Close()
		log.Printf("[MIXED] listen closed")
	}
}
