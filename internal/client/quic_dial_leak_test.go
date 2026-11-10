package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type closeTrackingPacketConn struct {
	net.PacketConn
	closed atomic.Bool
}

func (c *closeTrackingPacketConn) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}

func dialLeakTestTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h3"}}
}

// 回归：Dial 创建的 quic.Transport 与 UDP socket 未保存，Client.Close 只关 QUIC 连接，
// 每次重连泄漏一个 socket 与其后台协程。
func TestDialLeakClientCloseReleasesSocket(t *testing.T) {
	ln, err := quic.ListenAddr("127.0.0.1:0", dialLeakTestTLS(t), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-c.Context().Done() }()
		}
	}()

	var tracked *closeTrackingPacketConn
	cfg := DefaultTransportConfig(ln.Addr().String(), "localhost")
	cfg.TLSConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	cfg.RemoteUDPAddr = ln.Addr().(*net.UDPAddr)
	cfg.PacketConnFactory = func(ctx context.Context, network string) (net.PacketConn, error) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		tracked = &closeTrackingPacketConn{PacketConn: pc}
		return tracked, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := cl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if tracked == nil || !tracked.closed.Load() {
		t.Fatal("Client.Close did not close the underlying UDP socket")
	}
}

// 回归：多端口竞速全部失败时，循环依据 activeDials（发送方 defer 之后才递减）判断结束，
// 存在竞态，可能一直等到调用方超时并只返回 context 错误。
func TestDialLeakAllCandidatePortsFailReturnsPromptly(t *testing.T) {
	// 取三个当前无人监听的本地 UDP 端口
	var ports []int
	for i := 0; i < 3; i++ {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, pc.LocalAddr().(*net.UDPAddr).Port)
		_ = pc.Close()
	}
	cfg := DefaultTransportConfig("127.0.0.1:"+strconv.Itoa(ports[0]), "localhost")
	cfg.TLSConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	cfg.RemoteUDPAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ports[0]}
	cfg.AltPorts = ports[1:]
	cfg.ConnectTimeout = 300 * time.Millisecond
	cfg.PacketConnFactory = func(ctx context.Context, network string) (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := Dial(ctx, cfg)
	if err == nil {
		t.Fatal("Dial succeeded against closed ports")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("Dial took %v; it waited for the caller deadline instead of returning when all ports failed", elapsed)
	}
	if !strings.Contains(err.Error(), "candidate ports failed") {
		t.Fatalf("Dial error = %v, want the all-ports-failed error", err)
	}
}
