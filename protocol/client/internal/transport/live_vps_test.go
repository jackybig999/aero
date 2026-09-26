package transport

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestLiveDualVPS(t *testing.T) {
	targets := []struct {
		addr string
		sni  string
	}{
		{"myconsun.de5.net:443", "myconsun.de5.net"},
		{"myconsun.cc.cd:443", "myconsun.cc.cd"},
	}

	for _, tc := range targets {
		t.Run(tc.addr, func(t *testing.T) {
			d := net.Dialer{Timeout: 5 * time.Second}
			raw, err := d.Dial("tcp", tc.addr)
			if err != nil {
				t.Skipf("VPS %s not reachable via direct TCP: %v", tc.addr, err)
				return
			}
			defer raw.Close()

			cfg := BuildClientConfig(tc.sni)
			tlsConn := tls.Client(raw, cfg)
			tlsConn.SetDeadline(time.Now().Add(6 * time.Second))
			err = tlsConn.Handshake()
			if err != nil {
				t.Skipf("TLS Handshake to %s failed: %v", tc.addr, err)
				return
			}
			tlsConn.SetDeadline(time.Time{})
			state := tlsConn.ConnectionState()
			t.Logf("SUCCESS: connected to %s (ALPN=%s, PeerCerts=%d)",
				tc.addr, state.NegotiatedProtocol, len(state.PeerCertificates))
			if len(state.PeerCertificates) > 0 {
				leaf := state.PeerCertificates[0]
				t.Logf("Leaf: CN=%s, Issuer=%s, SPKI=%s",
					leaf.Subject.CommonName, leaf.Issuer.CommonName, CertSPKI(leaf))
			}
		})
	}
}
