package sub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
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

// fakeEdge 启动一个证书 SAN 含 example.com 的 TLS 服务，并让 edgeDo 信任它、把 example.com 解析到本机。
func fakeEdge(t *testing.T, h http.HandlerFunc) EndpointInfo {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	prevDial, prevTLS := edgeDial, edgeTLSConfig
	t.Cleanup(func() { edgeDial, edgeTLSConfig = prevDial, prevTLS })
	edgeTLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	edgeDial = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", portStr))
	}
	port, _ := strconv.Atoi(portStr)
	return EndpointInfo{VPSID: 7, Host: "example.com", Port: port, AdminKey: "adm", Installed: true}
}

func TestEdgeAPIOutcomes(t *testing.T) {
	ep := fakeEdge(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/cert/reload":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"domain":"n.example.com","issuer":"R11","not_after":1,"days_left":60}`))
		case "/admin/v1/restart":
			w.WriteHeader(http.StatusAccepted)
		case "/admin/v1/warp":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"type":"about:blank","title":"no local WARP proxy","code":"EDGE_WARP_UNAVAILABLE"}`))
		default: // 伪装站
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html></html>"))
		}
	})
	eps, _ := NewEndpointStore(filepath.Join(t.TempDir(), "eps.json"))
	_ = eps.Upsert(ep)
	svc := &VPSService{eps: eps}
	ctx := context.Background()

	if res, err := svc.RenewCert(ctx, 7, true); err != nil || !strings.Contains(res["message"].(string), "剩余 60 天") {
		t.Fatalf("renew: %v %v", res, err)
	}
	if _, err := svc.RestartEdge(ctx, 7); err != nil {
		t.Fatalf("restart: %v", err)
	}
	var st edgeRemoteStatus
	if err := edgeAPI(ctx, ep, http.MethodGet, "/admin/v1/status", nil, &st); !errors.Is(err, errEdgeAPIUnavailable) {
		t.Fatalf("cover page must map to errEdgeAPIUnavailable, got %v", err)
	}
	if err := edgeAPI(ctx, ep, http.MethodPut, "/admin/v1/warp", map[string]bool{"enabled": true}, nil); err == nil || !strings.Contains(err.Error(), "EDGE_WARP_UNAVAILABLE") {
		t.Fatalf("problem response: %v", err)
	}
	if _, err := svc.RestartEdge(ctx, 99); err == nil {
		t.Fatal("unknown vps accepted")
	}
}
