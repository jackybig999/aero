package sub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// edge 接口调用：域名不可解析时按 IP 直连但仍按域名校验证书；密钥只在 Authorization 头；
// 不受信任的证书与无域名节点一律不发送密钥。
func TestEdgeDoVerifiesTLSAndKeepsKeyInHeader(t *testing.T) {
	var gotAuth, gotQuery, gotHost string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotQuery, gotHost = r.Header.Get("Authorization"), r.URL.RawQuery, r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	prevDial, prevTLS := edgeDial, edgeTLSConfig
	t.Cleanup(func() { edgeDial, edgeTLSConfig = prevDial, prevTLS })
	edgeDial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		if host, _, _ := net.SplitHostPort(addr); host == "example.com" {
			return nil, errors.New("simulated DNS failure")
		}
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
	}
	ctx := context.Background()

	// 系统根证书不信任测试证书：拒绝
	if _, err := edgeDo(ctx, "example.com", "127.0.0.1", port, http.MethodGet, "/admin/status", "k-secret", nil, time.Second); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if gotAuth != "" {
		t.Fatal("credentials reached a peer whose certificate failed verification")
	}

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate()) // 测试证书的 SAN 含 example.com
	edgeTLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	resp, err := edgeDo(ctx, "example.com", "127.0.0.1", port, http.MethodGet, "/admin/status", "k-secret", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer k-secret" || gotQuery != "" || gotHost != "example.com" {
		t.Fatalf("auth=%q query=%q host=%q", gotAuth, gotQuery, gotHost)
	}

	if _, err := edgeDo(ctx, "198.51.100.1", "", port, http.MethodGet, "/admin/status", "k", nil, time.Second); !errors.Is(err, errEdgeNoDomain) {
		t.Fatalf("IP-only node: err = %v, want errEdgeNoDomain", err)
	}
}
