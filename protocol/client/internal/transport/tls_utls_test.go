package transport

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestUTLSChromeHandshakeWithServer(t *testing.T) {
	certX509, privKey := generateTestCert(t, "cdn-aero.com", false)

	// 注入 SPKI 钉扎以通过双轨安全校验
	pin := CertSPKI(certX509)
	AddPins(pin)
	defer ClearPins()

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certX509.Raw},
		PrivateKey:  privKey,
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, serverTLS)
	defer tlsLn.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		err = tlsConn.Handshake()
		serverDone <- err
	}()

	// 客户端使用 uTLS Chrome 指纹拨号
	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial raw: %v", err)
	}
	defer rawConn.Close()

	uCfg := BuildUTLSConfig("cdn-aero.com", FingerprintChrome)

	uconn, err := NewUConn(rawConn, uCfg, FingerprintChrome)
	if err != nil {
		t.Fatalf("NewUConn: %v", err)
	}
	defer uconn.Close()

	if err := uconn.HandshakeContext(); err != nil {
		t.Fatalf("uconn.HandshakeContext failed: %v", err)
	}

	if srvErr := <-serverDone; srvErr != nil {
		t.Fatalf("server TLS handshake failed: %v", srvErr)
	}

	negotiated := uconn.ConnectionState().NegotiatedProtocol
	t.Logf("[SUCCESS] uTLS Chrome Handshake OK! Negotiated ALPN: %s, TLS Version: 0x%04x",
		negotiated, uconn.ConnectionState().Version)
	if negotiated != "h2" {
		t.Errorf("expected ALPN h2, got %s", negotiated)
	}
}
