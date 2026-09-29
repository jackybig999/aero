package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/quic-go/quic-go"
)

func TestQUICWithCustomPacketConn(t *testing.T) {
	// 1. Create a local UDP listener with PacketConn
	pconn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer pconn.Close()

	// 2. Start a mock QUIC listener with self-signed certificate
	cert, err := generateSelfSignedTLSCert()
	if err != nil {
		t.Fatalf("generateTestCert failed: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	serverLn, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, &quic.Config{
		MaxIncomingStreams: 10,
	})
	if err != nil {
		t.Fatalf("quic.ListenAddr failed: %v", err)
	}
	defer serverLn.Close()

	// Accept in background
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		sconn, err := serverLn.Accept(ctx)
		if err == nil {
			_ = sconn.CloseWithError(0, "ok")
		}
	}()

	// 3. Dial using quic.Dial with custom pconn
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	clientTLS := defaultTLSConfig("localhost")
	clientTLS.InsecureSkipVerify = true
	quicConn, err := quic.Dial(ctx, pconn, serverLn.Addr(), clientTLS, &quic.Config{
		HandshakeIdleTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic.Dial with custom PacketConn failed: %v", err)
	}
	defer quicConn.CloseWithError(0, "client done")

	t.Logf("SUCCESS: QUIC connection established over custom PacketConn! LocalAddr: %s, RemoteAddr: %s",
		quicConn.LocalAddr(), quicConn.RemoteAddr())
}

func TestPhysicalUDPPacketConnBinding(t *testing.T) {
	// 1. Verify we can create a UDP PacketConn with IP_UNICAST_IF on Windows
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			_ = c.Control(func(fd uintptr) {
				// Use interface index 15 (detected physical Intel Wi-Fi 7)
				ifIndex := 15
				var buf [4]byte
				binary.BigEndian.PutUint32(buf[:], uint32(ifIndex))
				opErr = syscall.Setsockopt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, (*byte)(unsafe.Pointer(&buf[0])), 4)
			})
			return opErr
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pconn, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		t.Fatalf("ListenPacket with IP_UNICAST_IF failed: %v", err)
	}
	defer pconn.Close()

	t.Logf("SUCCESS: Created UDP PacketConn with IP_UNICAST_IF=15! LocalAddr: %s", pconn.LocalAddr())
}

func generateSelfSignedTLSCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
