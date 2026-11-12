package edge

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 证书来自宿主上的系统 ACME 客户端（用户决定 2026-11-12）：acme.sh 或 certbot，使用它们的默认位置。
// edge 只读这些目录、不签发、不修改；续期后证书文件变化由 DynamicCertLoader 热加载。

// systemCert 是找到的证书。
type systemCert struct {
	CertFile, KeyFile, Domain string
	NotAfter                  time.Time
}

// systemCertDirs 返回 acme.sh 与 certbot 的默认证书位置。
func systemCertDirs() []string {
	var dirs []string
	for _, env := range []string{"LE_WORKING_DIR", "ACME_HOME"} { // acme.sh 自定义安装目录
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			dirs = append(dirs, v, filepath.Join(v, ".acme.sh"))
		}
	}
	dirs = append(dirs, "/root/.acme.sh")
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, ".acme.sh"))
	}
	dirs = append(dirs, "/etc/letsencrypt/live") // certbot
	out := dirs[:0]
	seen := map[string]bool{}
	for _, d := range dirs {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// normalizeCertDomain 去掉端口、方括号与空白；IP 与 localhost 返回空（不为其查找证书）。
func normalizeCertDomain(d string) string {
	d = strings.TrimSpace(d)
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}
	d = strings.Trim(d, "[] ")
	if d == "" || d == "localhost" || net.ParseIP(d) != nil {
		return ""
	}
	return d
}

// findSystemCert 在 dirs 的每个子目录中查找证书：必须在有效期内、私钥匹配、覆盖 domain（含通配符）；
// domain 为空时接受任意有效证书并取其第一个非通配符名称。多个候选时取到期最晚者（最近一次续期）。
func findSystemCert(dirs []string, domain string, now time.Time) (systemCert, bool) {
	var best systemCert
	seen := map[string]bool{}
	for _, base := range dirs {
		base = strings.TrimSpace(base)
		if base == "" || seen[base] {
			continue
		}
		seen[base] = true
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			dir := filepath.Join(base, e.Name())
			if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
				continue
			}
			c, ok := loadCertDir(dir, strings.TrimSuffix(e.Name(), "_ecc"), domain, now)
			if ok && c.NotAfter.After(best.NotAfter) {
				best = c
			}
		}
	}
	return best, best.CertFile != ""
}

// loadCertDir 检查一个证书目录（acme.sh：<name>/fullchain.cer + <name>.key；certbot：live/<name>/fullchain.pem + privkey.pem）。
func loadCertDir(dir, name, domain string, now time.Time) (systemCert, bool) {
	certFile := firstNonEmptyFile(dir, "fullchain.cer", "fullchain.pem", "cert.pem")
	keyFile := firstNonEmptyFile(dir, name+".key", "privkey.pem", "privkey.key", "key.pem")
	if certFile == "" || keyFile == "" {
		return systemCert{}, false
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil || len(pair.Certificate) == 0 {
		return systemCert{}, false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return systemCert{}, false
	}
	if domain != "" {
		if leaf.VerifyHostname(domain) != nil {
			return systemCert{}, false
		}
	} else if domain = concreteName(leaf); domain == "" {
		return systemCert{}, false
	}
	return systemCert{CertFile: certFile, KeyFile: keyFile, Domain: domain, NotAfter: leaf.NotAfter}, true
}

// concreteName 返回证书中第一个非通配符名称（SAN 优先，其次 CN）。
func concreteName(c *x509.Certificate) string {
	for _, n := range append(append([]string{}, c.DNSNames...), c.Subject.CommonName) {
		if n = strings.TrimSpace(n); n != "" && !strings.Contains(n, "*") {
			return n
		}
	}
	return ""
}

func firstNonEmptyFile(dir string, names ...string) string {
	for _, n := range names {
		p := filepath.Join(dir, n)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Size() > 0 {
			return p
		}
	}
	return ""
}

// errNoSystemCert 说明证书从哪里找、如何准备（不在宿主上安装任何东西）。
func errNoSystemCert(domain string, dirs []string) error {
	if domain == "" {
		domain = "<节点域名>"
	}
	return fmt.Errorf("production edge server strictly requires valid TLS certificate: none for %s in %s; "+
		"issue one with the system acme.sh or certbot (default locations) or set cert_file/key_file "+
		"(self-signed cert is prohibited)", domain, strings.Join(dirs, ", "))
}
