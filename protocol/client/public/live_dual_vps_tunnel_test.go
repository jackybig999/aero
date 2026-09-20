package public

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/aero-protocol/aero-ech/internal/protocol"
	"github.com/aero-protocol/aero-ech/internal/transport"
	aeroproto "github.com/aero-protocol/proto"
	"golang.org/x/net/http2"
)

func TestLiveTunnelDualVPS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live VPS test in short mode")
	}
	nodes := []struct {
		name  string
		addr  string
		token string
		sni   string
		pins  []string
	}{
		{
			name:  "VPS 1 (Stable new with pin)",
			addr:  "myconsun.de5.net:443",
			token: "aero_65aa450a49293a85888d8195bbc81940",
			sni:   "myconsun.de5.net",
			pins:  []string{"N75oS2cgnhLGCuVcdWhBeyXX40746PDH3UqVghF9mzw="},
		},
		{
			name:  "VPS 2 (Previous stable without pin)",
			addr:  "myconsun.cc.cd:443",
			token: "aero_080381bf99afebe5bab9a5c92e84a59d",
			sni:   "myconsun.cc.cd",
			pins:  nil,
		},
	}

	for _, node := range nodes {
		t.Run(node.name, func(t *testing.T) {
			t.Logf("=== Testing %s (%s) ===", node.name, node.addr)

			// 1. Setup pins
			if len(node.pins) > 0 {
				transport.AddPins(node.pins...)
			}

			// 2. Dial Edge TLS
			d := net.Dialer{Timeout: 5 * time.Second}
			rawTCP, err := d.Dial("tcp", node.addr)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}
			defer rawTCP.Close()

			tlsCfg := transport.BuildClientConfig(node.sni)
			tlsCfg.NextProtos = []string{"h2", "http/1.1"}
			tlsConn := tls.Client(rawTCP, tlsCfg)
			tlsConn.SetDeadline(time.Now().Add(6 * time.Second))
			if err := tlsConn.Handshake(); err != nil {
				t.Fatalf("TLS Handshake failed: %v", err)
			}
			tlsConn.SetDeadline(time.Time{})
			t.Logf("TLS Handshake OK, ALPN=%s", tlsConn.ConnectionState().NegotiatedProtocol)

			// 3. HTTP/2 CONNECT Stream
			tr := &http2.Transport{AllowHTTP: false}
			cc, err := tr.NewClientConn(tlsConn)
			if err != nil {
				t.Fatalf("NewClientConn failed: %v", err)
			}
			defer cc.Close()

			pr, pw := io.Pipe()
			defer pw.Close()

			req := &http.Request{
				Method: http.MethodConnect,
				URL: &url.URL{
					Scheme: "https",
					Host:   node.addr,
					Opaque: "www.google.com:443",
				},
				Host: "www.google.com:443",
				Header: http.Header{
					"Proxy-Authorization": []string{"Bearer " + node.token},
				},
				Body:          pr,
				ContentLength: -1,
			}

			type res struct {
				resp *http.Response
				err  error
			}
			ch := make(chan res, 1)
			go func() {
				resp, err := cc.RoundTrip(req)
				ch <- res{resp, err}
			}()

			// Send ConnectRequest
			connectReq := &aeroproto.ConnectRequest{
				Version:   "aero/2.0",
				Token:     node.token,
				Nonce:     generateNonce(),
				Timestamp: uint64(time.Now().UnixMilli()),
				Streams: []*aeroproto.StreamSpec{{
					StreamId:   1,
					StreamType: aeroproto.StreamType_GENERAL,
					TargetHost: "www.google.com",
					TargetPort: 443,
				}},
			}
			var buf bytes.Buffer
			_ = protocol.WriteMessage(&buf, connectReq)
			preface := buf.Bytes()
			go func() {
				_, _ = pw.Write(preface)
			}()

			select {
			case r := <-ch:
				if r.err != nil {
					t.Fatalf("H2 CONNECT failed: %v", r.err)
				}
				if r.resp.StatusCode != 200 {
					t.Fatalf("H2 CONNECT returned status: %d", r.resp.StatusCode)
				}
				t.Logf("H2 CONNECT response: %d Connection Established", r.resp.StatusCode)

				// Read ConnectResponse
				tunnel := newStreamConn(r.resp.Body, pw, rawTCP)
				defer tunnel.Close()
				tunnel.SetDeadline(time.Now().Add(6 * time.Second))
				var connectResp aeroproto.ConnectResponse
				if err := protocol.ReadMessage(tunnel, &connectResp); err != nil {
					t.Fatalf("Read ConnectResponse failed: %v", err)
				}
				t.Logf("AERO Handshake OK! SessionID=%s, HBInterval=%d, Accepted=%v",
					connectResp.SessionId, connectResp.HeartbeatInterval, connectResp.Accepted)
				if !connectResp.Accepted {
					t.Fatalf("ConnectResponse indicated rejected: %s", connectResp.Message)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("H2 CONNECT timed out")
			}
		})
	}
}

type streamConn struct {
	r   io.Reader
	w   io.Writer
	raw net.Conn
}

func newStreamConn(r io.Reader, w io.Writer, raw net.Conn) *streamConn {
	return &streamConn{r: r, w: w, raw: raw}
}

func (s *streamConn) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *streamConn) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *streamConn) Close() error {
	if c, ok := s.r.(io.Closer); ok {
		_ = c.Close()
	}
	if c, ok := s.w.(io.Closer); ok {
		_ = c.Close()
	}
	return nil
}
func (s *streamConn) LocalAddr() net.Addr                { return s.raw.LocalAddr() }
func (s *streamConn) RemoteAddr() net.Addr               { return s.raw.RemoteAddr() }
func (s *streamConn) SetDeadline(t time.Time) error      { return s.raw.SetDeadline(t) }
func (s *streamConn) SetReadDeadline(t time.Time) error  { return s.raw.SetReadDeadline(t) }
func (s *streamConn) SetWriteDeadline(t time.Time) error { return s.raw.SetWriteDeadline(t) }
