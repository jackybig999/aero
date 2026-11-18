package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// 订阅拉取只允许 https（C5 §1）：测试用一个临时 CA 按 SNI 现签叶子证书，
// 客户端通过 subRootCAsForTest 信任这个 CA，证书与主机名校验照常进行（不跳过校验）。

var (
	subTestCAOnce sync.Once
	subTestCACert *x509.Certificate
	subTestCAKey  *ecdsa.PrivateKey
	subTestPool   *x509.CertPool

	subTestLeafMu sync.Mutex
	subTestLeaves = map[string]*tls.Certificate{}
)

func initSubTestCA() {
	subTestCAOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "aero test sub CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}
		subTestCACert, subTestCAKey = cert, key
		subTestPool = x509.NewCertPool()
		subTestPool.AddCert(cert)
	})
}

// subTestLeaf 返回对 name 有效的叶子证书（按名字缓存）。
func subTestLeaf(name string) (*tls.Certificate, error) {
	initSubTestCA()
	subTestLeafMu.Lock()
	defer subTestLeafMu.Unlock()
	if c, ok := subTestLeaves[name]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, subTestCACert, &key.PublicKey, subTestCAKey)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	subTestLeaves[name] = c
	return c, nil
}

// newInMemHTTPSDialer 与 newInMemHTTPDialer 相同，但服务端在内存管道上做 TLS（证书按客户端 SNI 现签）。
func newInMemHTTPSDialer(handler http.Handler) func(ctx context.Context, network, addr string) (net.Conn, error) {
	srvCfg := &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hi.ServerName
			if name == "" {
				name = "default.aero.test"
			}
			return subTestLeaf(name)
		},
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		cliConn, srvConn := net.Pipe()
		go func() {
			defer srvConn.Close()
			tc := tls.Server(srvConn, srvCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			defer tc.Close()
			req, err := http.ReadRequest(bufio.NewReader(tc))
			if err != nil {
				return
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			_ = rec.Result().Write(tc)
		}()
		return cliConn, nil
	}
}

// useSubHTTPS 安装内存 HTTPS 订阅服务：物理拨号钩子、测试根证书；缓存目录指向临时目录；清理端口缓存。
func useSubHTTPS(t *testing.T, handler http.Handler) {
	t.Helper()
	initSubTestCA()
	ClearCachedSubPorts()
	SetPhysicalDialerHook(newInMemHTTPSDialer(handler))
	subRootCAsForTest.Store(subTestPool)
	t.Setenv("AERO_DATA_DIR", t.TempDir())
	t.Cleanup(func() {
		SetPhysicalDialerHook(nil)
		subRootCAsForTest.Store(nil)
		ClearCachedSubPorts()
	})
}

// syncBuffer 并发安全的日志缓冲。
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLog 把标准 log 输出收进缓冲，测试结束后恢复。
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return buf
}

// subJSONFor 生成一份只含一个合法节点的订阅 JSON。
func subJSONFor(addr, token string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	// 带 ip：应用订阅时引擎不必再解析节点域名（测试环境没有 DNS）
	ip := host
	if net.ParseIP(host) == nil {
		ip = "198.51.100.7"
	}
	return fmt.Sprintf(`{"version":"aero/3.0","userId":"u","servers":[{"name":"n","host":%q,"address":%q,"ip":%q,"token":%q,"sni":%q,"protocol":"connect-ip"}]}`, host, addr, ip, token, host)
}

func TestMain(m *testing.M) {
	// 订阅缓存写到客户端数据目录：整个测试进程用临时目录，不碰本机真实目录
	dir, err := os.MkdirTemp("", "aero-client-test-data-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: cannot create temp data dir:", err)
		os.Exit(1)
	}
	os.Setenv("AERO_DATA_DIR", dir)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
