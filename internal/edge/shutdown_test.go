package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// 回归（L0 §8.6）：停机时 Transport 被直接关闭，不发送 CONNECTION_CLOSE，客户端要等空闲超时
// （90 秒）才发现断线。Shutdown 必须先摘除 readiness，再通知在线连接，存活探针保持成功。
func TestShutdownNotifiesClientsAndFlipsReadiness(t *testing.T) {
	listenAddr, host := findTestAddr()
	srv, err := NewServer(ServerConfig{Listen: listenAddr, Domain: host, DataDir: t.TempDir(), Token: "shutdown_token", AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qConn, err := quic.DialAddr(ctx, srv.quicListener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer qConn.CloseWithError(0, "")

	// 一次鉴权请求，让连接绑定 token 并被跟踪。
	h3 := (&http3.Transport{}).NewClientConn(qConn)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader(make([]byte, 12)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Authorization", "Bearer shutdown_token")
	req.Header.Set("Aero-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set("Aero-Nonce", hex.EncodeToString(bytes.Repeat([]byte{0x3c}, 32)))
	resp, err := h3.RoundTrip(req)
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	_ = resp.Body.Close()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case <-qConn.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("client was not notified of the shutdown (no CONNECTION_CLOSE)")
	}
	var appErr *quic.ApplicationError
	if !errors.As(context.Cause(qConn.Context()), &appErr) || !appErr.Remote || appErr.ErrorMessage != "server shutting down" {
		t.Fatalf("client close cause = %v, want remote application close \"server shutting down\"", context.Cause(qConn.Context()))
	}

	if rec := probeRequest(srv, "/readyz", "127.0.0.1:5000"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz after shutdown = %d, want 503", rec.Code)
	}
	if rec := probeRequest(srv, "/healthz", "127.0.0.1:5000"); rec.Code != http.StatusOK {
		t.Fatalf("/healthz after shutdown = %d, want 200 (liveness must not fail on drain)", rec.Code)
	}
}
