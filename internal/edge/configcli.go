// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 节点上的 `aero-edge config` 与 `aero-edge check`（供运维命令 aero 调用）。
// edge 的配置文件只由 edge 自己读写：aero 不再用 sed/python 改 edge.json，统一经这里校验后原子写入。
// 修改后由 aero 执行 check，全部通过再重启服务生效（用户 2026-11-17：安装只装服务端，其余在节点上用命令完成）。

// ErrNoCertificate 表示没有可用的 TLS 证书；edge 此时不对外监听，等待 `aero setup` 完成证书后重启。
var ErrNoCertificate = errors.New("no usable TLS certificate")

var (
	nodeDomainRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}$`)
	adminKeyRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
)

// minAdminKeyLen 是管理密钥的最短长度：C13 对公网开放，密钥是唯一凭据。
const minAdminKeyLen = 32

// configKeys 是允许经命令行修改的配置项（其余配置由 edge 自己维护）。
var configKeys = []string{"domain", "listen", "admin_key", "warp", "usage_api", "remote_admin_v1", "connect_ip", "token_issuer", "congestion_control"}

func readConfigMap(path string) (map[string]any, error) {
	m := map[string]any{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// ConfigSet 校验并写入一项配置（原子替换，新文件 0600）。value 为 "random" 的 admin_key 自动生成。
// 返回实际写入的值（生成的密钥由调用方显示给运维一次）。
func ConfigSet(path, key, value string) (string, error) {
	m, err := readConfigMap(path)
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	switch key {
	case "domain":
		if !nodeDomainRe.MatchString(value) {
			return "", fmt.Errorf("invalid domain %q", value)
		}
		m["domain"] = strings.ToLower(value)
		value = strings.ToLower(value)
		// 换域名时，位于系统 ACME 默认目录的证书路径属于旧域名：删除，由 edge 按新域名重新发现
		if cf, _ := m["cert_file"].(string); cf != "" && underSystemCertDir(cf) {
			delete(m, "cert_file")
			delete(m, "key_file")
		}
	case "listen":
		p, err := strconv.Atoi(strings.TrimPrefix(value, ":"))
		if err != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("invalid port %q", value)
		}
		value = ":" + strconv.Itoa(p)
		m["listen"] = value
	case "admin_key":
		if value == "random" {
			k, err := randomHexBytes(32)
			if err != nil {
				return "", err
			}
			value = k
		}
		if !adminKeyRe.MatchString(value) {
			return "", fmt.Errorf("admin key must be %d-128 characters of [A-Za-z0-9_-]", minAdminKeyLen)
		}
		m["admin_key"] = value
	case "warp": // off | ai | all：只使用本机官方 WARP 客户端的代理，edge 不安装 WARP
		switch value {
		case "off":
			m["warp_proxy"], m["warp_all"] = "", false
		case "ai", "all":
			m["warp_proxy"], m["warp_all"] = warpLocalProxy, value == "all"
		default:
			return "", fmt.Errorf("warp must be off, ai or all")
		}
	case "token_issuer": // <kid>:<base64 Ed25519 公钥>，加入 token_issuers（C3）
		kid, pub, _ := strings.Cut(value, ":")
		if _, err := parseTokenIssuers(map[string]string{kid: pub}); err != nil {
			return "", err
		}
		iss, _ := m["token_issuers"].(map[string]any)
		if iss == nil {
			iss = map[string]any{}
		}
		iss[kid] = pub
		m["token_issuers"] = iss
	case "congestion_control":
		if !ValidCongestionControl(value) {
			return "", fmt.Errorf("congestion_control must be lossy or cubic")
		}
		m[key] = value
	case "usage_api", "remote_admin_v1", "connect_ip":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return "", fmt.Errorf("%s must be true or false", key)
		}
		m[key] = b
	default:
		return "", fmt.Errorf("unknown or read-only key %q (allowed: %s)", key, strings.Join(configKeys, ", "))
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return value, replaceFileAtomic(path, data, 0o600)
}

// ConfigGet 返回一项配置的当前值（warp 以 off/ai/all 表示；未设置为空串）。
func ConfigGet(path, key string) (string, error) {
	m, err := readConfigMap(path)
	if err != nil {
		return "", err
	}
	switch key {
	case "warp":
		if p, _ := m["warp_proxy"].(string); p == "" {
			return "off", nil
		}
		if all, _ := m["warp_all"].(bool); all {
			return "all", nil
		}
		return "ai", nil
	case "congestion_control": // 未设置或无效时返回默认值（不含环境变量覆盖），方便 aero cc 直接显示当前生效的取值
		if v, _ := m[key].(string); ValidCongestionControl(v) {
			return v, nil
		}
		return DefaultCongestionControl, nil
	case "domain", "listen", "admin_key", "usage_api", "remote_admin_v1", "connect_ip", "metering_key", "node_id", "cert_file", "key_file", "data_dir":
		if v, ok := m[key]; ok && v != nil {
			return fmt.Sprint(v), nil
		}
		return "", nil
	}
	return "", fmt.Errorf("unknown key %q", key)
}

// CheckItem 是一项检查结果。Level：OK、WARN、FAIL。
type CheckItem struct {
	Level, Name, Detail string
}

// CheckNode 检查节点是否可以（重新）启动并对外服务：配置、域名、证书、管理密钥、端口、防火墙工具、TUN、WARP。
// 只读：不修改宿主与配置。有 FAIL 时运维不应重启服务。
func CheckNode(path string) []CheckItem {
	var out []CheckItem
	add := func(level, name, format string, a ...any) {
		out = append(out, CheckItem{level, name, fmt.Sprintf(format, a...)})
	}
	var cfg ServerConfig
	b, err := os.ReadFile(path)
	if err != nil {
		add("FAIL", "config", "read %s: %v", path, err)
		return out
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		add("FAIL", "config", "parse %s: %v", path, err)
		return out
	}
	add("OK", "config", "%s", path)
	if cc := strings.TrimSpace(cfg.CongestionControl); cc != "" && !ValidCongestionControl(cc) {
		add("FAIL", "congestion_control", "%q is invalid (aero-edge config set congestion_control lossy|cubic)", cc)
	} else {
		add("OK", "congestion_control", "%s", ResolveCongestionControl(cc))
	}
	isIngress := strings.EqualFold(strings.TrimSpace(cfg.Role), "ingress")
	if isIngress {
		if strings.TrimSpace(cfg.NextHopAddr) == "" {
			add("FAIL", "role", "ingress requires next_hop_addr (aero-edge config set next_hop_addr <出口地址:端口>)")
		} else if strings.TrimSpace(cfg.HopCredential) == "" {
			add("FAIL", "role", "ingress requires hop_credential")
		} else {
			add("OK", "role", "ingress -> %s (TCP/UDP/DoH forwarded; CONNECT-IP disabled)", cfg.NextHopAddr)
		}
	}

	domain := normalizeCertDomain(cfg.Domain)
	if !nodeDomainRe.MatchString(domain) {
		add("FAIL", "domain", "not set or invalid (aero setup / aero-edge config set domain <域名>)")
	} else {
		add("OK", "domain", "%s", domain)
	}

	if ci, err := checkCertificate(cfg, domain); err != nil {
		add("FAIL", "certificate", "%v", err)
	} else {
		add("OK", "certificate", "%s (expires %s, %d days)", ci.file, ci.notAfter.UTC().Format("2006-01-02"), int(time.Until(ci.notAfter).Hours()/24))
	}

	switch {
	case cfg.AdminKey == "":
		add("WARN", "admin_key", "not set: edge generates a random key on first start")
	case len(cfg.AdminKey) < minAdminKeyLen:
		add("FAIL", "admin_key", "only %d characters; the remote management API needs at least %d (aero key)", len(cfg.AdminKey), minAdminKeyLen)
	default:
		add("OK", "admin_key", "%d characters", len(cfg.AdminKey))
	}

	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "/var/lib/aero"
	}
	listen := cfg.Listen
	if listen == "" {
		listen = ":443"
	}
	switch running, err := edgeInstanceRunning(dataDir); {
	case err != nil:
		add("WARN", "listen", "%s: cannot tell whether edge is running (%v); port test skipped", listen, err)
	case running:
		add("OK", "listen", "%s (edge is running; port test skipped)", listen)
	default:
		if addr, moved := selectListenAddr(listen, StandardCandidatePorts, checkPortAvailable); !moved && !checkPortAvailable(listen) {
			add("FAIL", "listen", "%s and all candidate ports are occupied", listen)
		} else if moved {
			add("WARN", "listen", "%s is occupied by another program; edge will rotate to %s", listen, addr)
		} else {
			add("OK", "listen", "%s free (TCP+UDP)", listen)
		}
	}

	if isIngress {
		add("OK", "connect_ip", "disabled on ingress: no TUN, host untouched")
	} else if cfg.ConnectIP != nil && !*cfg.ConnectIP {
		add("OK", "connect_ip", "disabled by config: TCP/UDP proxy and DoH only, no TUN, host untouched")
	} else {
		if fw, err := firewallBackend(); err != nil {
			add("FAIL", "firewall", "%v (or aero-edge config set connect_ip false)", err)
		} else {
			add("OK", "firewall", "%s", fw)
		}
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			add("FAIL", "tun", "/dev/net/tun unavailable: %v (or aero-edge config set connect_ip false)", err)
		} else {
			add("OK", "tun", "/dev/net/tun")
		}
	}

	switch {
	case cfg.WarpProxy == "" && warpLocalProxyAvailable():
		add("OK", "warp", "off (local official WARP proxy available; aero warp ai|all to use it)")
	case cfg.WarpProxy == "":
		add("OK", "warp", "off")
	case warpLocalProxyAvailable():
		add("OK", "warp", "on via %s (all=%v)", cfg.WarpProxy, cfg.WarpAll)
	default:
		add("FAIL", "warp", "enabled but no WARP proxy on %s (aero warp install, or aero warp off)", cfg.WarpProxy)
	}
	return out
}

// edgeInstanceRunning 只读地判断数据目录是否被运行中的 edge 占用：数据目录或 edge.lock 不存在
// （全新安装、从未运行）说明没有实例，不创建任何文件；锁被占用才返回 true；其他错误原样返回。
func edgeInstanceRunning(dataDir string) (bool, error) {
	if _, err := os.Stat(filepath.Join(dataDir, "edge.lock")); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	lock, err := acquireInstanceLock(dataDir)
	if err != nil {
		if isInstanceLockBusy(err) {
			return true, nil
		}
		return false, err
	}
	_ = lock.release()
	return false, nil
}

// isInstanceLockBusy 判断 acquireInstanceLock 的错误是否表示“锁已被另一个实例持有”。
func isInstanceLockBusy(err error) bool {
	return errors.Is(err, errInstanceLockBusy)
}

type certCheck struct {
	file     string
	notAfter time.Time
}

// checkCertificate 按与启动相同的规则找证书：显式 cert_file/key_file 优先，否则系统 acme.sh/certbot 默认位置。
func checkCertificate(cfg ServerConfig, domain string) (certCheck, error) {
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return certCheck{}, fmt.Errorf("cert_file/key_file: %w", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return certCheck{}, err
		}
		if time.Now().After(leaf.NotAfter) {
			return certCheck{}, fmt.Errorf("%s expired on %s", cfg.CertFile, leaf.NotAfter.UTC().Format("2006-01-02"))
		}
		if domain != "" && leaf.VerifyHostname(domain) != nil {
			return certCheck{}, fmt.Errorf("%s does not cover %s", cfg.CertFile, domain)
		}
		return certCheck{cfg.CertFile, leaf.NotAfter}, nil
	}
	if domain == "" {
		return certCheck{}, errors.New("domain not set")
	}
	c, ok := findSystemCert(systemCertDirs(), domain, time.Now())
	if !ok {
		return certCheck{}, fmt.Errorf("none for %s in %s (aero cert)", domain, strings.Join(systemCertDirs(), ", "))
	}
	return certCheck{c.CertFile, c.NotAfter}, nil
}

// underSystemCertDir 报告 path 是否位于 acme.sh/certbot 的默认证书目录下。
func underSystemCertDir(path string) bool {
	for _, d := range systemCertDirs() {
		if rel, err := filepath.Rel(d, path); err == nil && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}

// ConsoleURLFromConfig 只读：按配置文件计算控制台完整网址 https://<domain>[:端口]/console/<h>/#k=<key>（端口 443 省略）。
// 输出含密钥，仅供 `aero info` 有意显示。
func ConsoleURLFromConfig(path string) (string, error) {
	domain, err := ConfigGet(path, "domain")
	if err != nil {
		return "", err
	}
	key, err := ConfigGet(path, "admin_key")
	if err != nil {
		return "", err
	}
	listen, err := ConfigGet(path, "listen")
	if err != nil {
		return "", err
	}
	if domain == "" {
		return "", fmt.Errorf("domain is not set")
	}
	if len(key) < minAdminKeyLen {
		return "", fmt.Errorf("admin_key shorter than %d characters (run `aero key`)", minAdminKeyLen)
	}
	port := 443
	if listen != "" {
		ps := listen
		if _, p, err := net.SplitHostPort(listen); err == nil {
			ps = p
		}
		ps = strings.TrimPrefix(ps, ":")
		if n, err := strconv.Atoi(ps); err == nil && n > 0 && n < 65536 {
			port = n
		}
	}
	return ConsoleURL(domain, port, key), nil
}
