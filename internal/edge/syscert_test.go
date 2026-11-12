package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert 在 dir 写入覆盖 names 的证书与私钥（文件名按 acme.sh 或 certbot 约定）。
func writeTestCert(t *testing.T, dir, certName, keyName string, notAfter time.Time, names ...string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(priv)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cf, kf := filepath.Join(dir, certName), filepath.Join(dir, keyName)
	_ = os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cf, kf
}

func TestFindSystemCertAcmeAndCertbot(t *testing.T) {
	root := t.TempDir()
	acme, live := filepath.Join(root, ".acme.sh"), filepath.Join(root, "live")
	dirs := []string{"/nonexistent/12345", "", acme, live}
	now := time.Now()
	day := 24 * time.Hour

	// acme.sh 单域名（ECC 目录）
	cf, kf := writeTestCert(t, filepath.Join(acme, "a.example.com_ecc"), "fullchain.cer", "a.example.com.key", now.Add(60*day), "a.example.com")
	for _, d := range []string{"a.example.com", "a.example.com:2083", "[a.example.com]", "  a.example.com "} {
		c, ok := findSystemCert(dirs, normalizeCertDomain(d), now)
		if !ok || c.CertFile != cf || c.KeyFile != kf {
			t.Fatalf("%q: %+v %v", d, c, ok)
		}
	}
	// certbot 通配符（目录名是基础域名，节点用随机子域名）
	cbf, _ := writeTestCert(t, filepath.Join(live, "example.org"), "fullchain.pem", "privkey.pem", now.Add(80*day), "example.org", "*.example.org")
	if c, ok := findSystemCert(dirs, "x7k2.example.org", now); !ok || c.CertFile != cbf {
		t.Fatalf("wildcard via certbot: %+v %v", c, ok)
	}
	// acme.sh 通配符目录名（*.example.net_ecc）
	wf, _ := writeTestCert(t, filepath.Join(acme, "*.example.net_ecc"), "fullchain.cer", "*.example.net.key", now.Add(30*day), "*.example.net")
	if c, ok := findSystemCert(dirs, "node1.example.net", now); !ok || c.CertFile != wf {
		t.Fatalf("wildcard via acme.sh: %+v %v", c, ok)
	}
	// 通配符不覆盖多级子域名与基础域名
	for _, d := range []string{"a.b.example.net", "example.net"} {
		if _, ok := findSystemCert(dirs, d, now); ok {
			t.Fatalf("%s must not match *.example.net", d)
		}
	}
	// 多张有效证书：取到期最晚者（最近一次续期）
	newer, _ := writeTestCert(t, filepath.Join(acme, "a.example.com"), "fullchain.cer", "a.example.com.key", now.Add(89*day), "a.example.com")
	if c, _ := findSystemCert(dirs, "a.example.com", now); c.CertFile != newer {
		t.Fatalf("latest renewal not chosen: %s", c.CertFile)
	}
	// 未配置域名：取任意有效证书的具体名称（不会取通配符）
	if c, ok := findSystemCert(dirs, "", now); !ok || c.Domain == "" || c.Domain[0] == '*' {
		t.Fatalf("auto domain: %+v %v", c, ok)
	}
}

func TestFindSystemCertRejectsUnusable(t *testing.T) {
	root := t.TempDir()
	acme := filepath.Join(root, ".acme.sh")
	now := time.Now()
	// 已过期
	writeTestCert(t, filepath.Join(acme, "old.example.com_ecc"), "fullchain.cer", "old.example.com.key", now.Add(-time.Hour), "old.example.com")
	// 私钥与证书不匹配
	writeTestCert(t, filepath.Join(acme, "mix.example.com"), "fullchain.cer", "x.key", now.Add(time.Hour), "mix.example.com")
	_, otherKey := writeTestCert(t, filepath.Join(root, "other"), "c.pem", "k.pem", now.Add(time.Hour), "mix.example.com")
	kb, _ := os.ReadFile(otherKey)
	_ = os.WriteFile(filepath.Join(acme, "mix.example.com", "mix.example.com.key"), kb, 0o600)
	// 0 字节文件、缺私钥
	_ = os.MkdirAll(filepath.Join(acme, "empty.example.com"), 0o755)
	_ = os.WriteFile(filepath.Join(acme, "empty.example.com", "fullchain.cer"), nil, 0o644)
	// 普通文件当作基础目录
	file := filepath.Join(root, "file")
	_ = os.WriteFile(file, []byte("x"), 0o644)

	for _, d := range []string{"old.example.com", "mix.example.com", "empty.example.com"} {
		if c, ok := findSystemCert([]string{acme, file}, d, now); ok {
			t.Errorf("%s: unusable certificate accepted: %+v", d, c)
		}
	}
	for _, h := range []string{"127.0.0.1", "::1", "localhost", "10.0.0.1"} {
		if normalizeCertDomain(h) != "" {
			t.Errorf("%s must not be used for certificate lookup", h)
		}
	}
}
