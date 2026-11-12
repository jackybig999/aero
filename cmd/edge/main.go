// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/aero-protocol/aero/internal/edge"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "cleanup-host" {
		os.Exit(cleanupHostCmd(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "check-cert" {
		os.Exit(checkCertCmd(os.Args[2:]))
	}
	showVer := flag.Bool("version", false, "print version and exit")
	listen := flag.String("listen", ":443", "listen address (e.g. :443)")
	domain := flag.String("domain", "", "public domain or SNI")
	token := flag.String("token", "", "initial bootstrap token (auto-generated if empty)")
	certFile := flag.String("cert", "", "path to TLS cert PEM")
	keyFile := flag.String("key", "", "path to TLS key PEM")
	dataDir := flag.String("data-dir", defaultDataDir(), "data directory for tokens.json and client-sub.json")
	adminKey := flag.String("admin-key", "", "remote Admin API key (X-Aero-Admin-Key)")
	profile := flag.String("profile", "small", "performance profile: tiny|small|medium")
	maxConn := flag.Int("max-conn", 0, "max active tunnels global (0=default)")
	maxConnUser := flag.Int("max-conn-user", 0, "max active tunnels per user token (0=default)")
	rateIP := flag.Int("rate-ip", 0, "max incoming connections/s/IP (0=default)")
	bwUser := flag.Int("bw-user", 0, "max bandwidth bytes/s per user (0=unlimited)")
	advHost := flag.String("advertise-host", "", "public advertise host in subscription")
	coverName := flag.String("cover-name", "CloudEdge CDN", "cover site title")
	allowSelfSigned := flag.Bool("allow-self-signed-test", false, "allow self-signed certs and loopback targets for testing")
	configPath := flag.String("config", "", "path to JSON configuration file")
	warpProxy := flag.String("warp-proxy", "", "WARP egress plugin: local SOCKS5 of the official client, e.g. 127.0.0.1:40000 (empty = off; toggle in console)")
	warpAll := flag.Bool("warp-all", false, "route all outbound traffic via WARP proxy instead of only AI & Google domains")
	globalTUNDevice := flag.String("global-tun", "", "shared TUN device name for CONNECT-IP NAT (e.g. aero-tun0)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "AERO edge v%s — high-performance protocol edge node\n\n", edge.Version)
		fmt.Fprintf(os.Stderr, "Usage: aero-edge [options]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("aero-edge %s (protocol=%s, api_level=%d)\n", edge.Version, edge.Protocol, edge.APILevel)
		return
	}

	raiseFileLimits()

	cfg := edge.ServerConfig{
		Listen:                     *listen,
		Domain:                     *domain,
		Token:                      *token,
		CertFile:                   *certFile,
		KeyFile:                    *keyFile,
		DataDir:                    *dataDir,
		AdminKey:                   *adminKey,
		Profile:                    *profile,
		MaxConn:                    *maxConn,
		MaxConnUser:                *maxConnUser,
		RateIP:                     *rateIP,
		BWUser:                     *bwUser,
		AdvertiseHost:              *advHost,
		CoverName:                  *coverName,
		AllowSelfSignedCertForTest: *allowSelfSigned,
		WarpProxy:                  *warpProxy,
		WarpAll:                    *warpAll,
		GlobalTUNDevice:            *globalTUNDevice,
	}

	targetConfig := *configPath
	if targetConfig == "" {
		if _, err := os.Stat("/etc/aero/edge.json"); err == nil {
			targetConfig = "/etc/aero/edge.json"
		}
	}

	if targetConfig != "" {
		data, err := os.ReadFile(targetConfig)
		if err != nil {
			log.Fatalf("failed to read config file %s: %v", targetConfig, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("failed to parse config file %s: %v", targetConfig, err)
		}
		if *globalTUNDevice != "" {
			cfg.GlobalTUNDevice = *globalTUNDevice
		}
		log.Printf("[CONFIG] loaded configuration from %s", targetConfig)
	}

	// edge 持久化自身配置的路径：显式 --config 或已存在的 /etc/aero/edge.json；
	// 首次以 root 在 Linux 运行时创建 /etc/aero/edge.json。其他情况不持久化。
	switch {
	case targetConfig != "":
		cfg.ConfigPath = targetConfig
	case runtime.GOOS == "linux" && os.Geteuid() == 0:
		cfg.ConfigPath = "/etc/aero/edge.json"
	}

	// Apply profiles if not explicitly overridden
	applyProfileDefaults(&cfg)

	log.Printf("[INIT] starting AERO edge server %s on %s...", edge.Version, cfg.Listen)
	if err := edge.Run(cfg); err != nil {
		log.Fatalf("fatal server error: %v", err)
	}
}

func applyProfileDefaults(cfg *edge.ServerConfig) {
	switch cfg.Profile {
	case "tiny":
		if cfg.MaxConn == 0 {
			cfg.MaxConn = 512
		}
		if cfg.MaxConnUser == 0 {
			cfg.MaxConnUser = 128
		}
		if cfg.RateIP == 0 {
			cfg.RateIP = 50
		}
	case "medium":
		if cfg.MaxConn == 0 {
			cfg.MaxConn = 8192
		}
		if cfg.MaxConnUser == 0 {
			cfg.MaxConnUser = 2048
		}
		if cfg.RateIP == 0 {
			cfg.RateIP = 400
		}
	default: // "small" or custom
		if cfg.MaxConn == 0 {
			cfg.MaxConn = edge.DefaultMaxGlobal
		}
		if cfg.MaxConnUser == 0 {
			cfg.MaxConnUser = edge.DefaultMaxPerTok
		}
		if cfg.RateIP == 0 {
			cfg.RateIP = 200
		}
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return "/var/lib/aero"
	}
	return "./data"
}

// checkCertCmd 实现 `aero-edge check-cert -domain D`：只读检查系统 acme.sh/certbot 默认位置是否有覆盖 D 的
// 有效证书（与启动时规则相同），以 KEY=VALUE 行输出，供安装前预检。始终退出 0，结果看 CERT_FOUND。
func checkCertCmd(args []string) int {
	fs := flag.NewFlagSet("check-cert", flag.ContinueOnError)
	domain := fs.String("domain", "", "node domain")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r := edge.CheckSystemCert(*domain)
	yes := map[bool]string{true: "yes", false: "no"}
	fmt.Printf("CERT_DOMAIN=%s\nCERT_FOUND=%s\nACME_SH=%s\nCERTBOT=%s\n", r.Domain, yes[r.Found], yes[r.ACMESh], yes[r.Certbot])
	if r.Found {
		fmt.Printf("CERT_FILE=%s\nCERT_NOT_AFTER=%s\n", r.CertFile, r.NotAfter.UTC().Format(time.RFC3339))
	}
	fmt.Printf("CERT_SEARCHED=%s\n", strings.Join(r.Searched, ","))
	return 0
}

// cleanupHostCmd 实现 `aero-edge cleanup-host [-data-dir DIR] [-config FILE]`：edge 停止后还原宿主状态
// （带标记的规则、ip_forward）。供 systemd ExecStopPost 调用（含崩溃），也可手动执行；edge 运行中时拒绝。
// 数据目录与服务一致：-data-dir 优先，其次配置文件的 data_dir（-config 或已存在的 /etc/aero/edge.json），最后默认值。
func cleanupHostCmd(args []string) int {
	fs := flag.NewFlagSet("cleanup-host", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "edge data directory (default: config data_dir, else "+defaultDataDir()+")")
	configPath := fs.String("config", "", "edge config file (default: /etc/aero/edge.json if present)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir := *dataDir
	if dir == "" {
		path := *configPath
		if path == "" {
			if _, err := os.Stat("/etc/aero/edge.json"); err == nil {
				path = "/etc/aero/edge.json"
			}
		}
		if path != "" {
			var c struct {
				DataDir string `json:"data_dir"`
			}
			b, err := os.ReadFile(path)
			if err == nil {
				err = json.Unmarshal(b, &c)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "cleanup-host: read %s: %v\n", path, err)
				return 1
			}
			dir = c.DataDir
		}
	}
	if dir == "" {
		dir = defaultDataDir()
	}
	if err := edge.CleanupHost(dir); err != nil {
		fmt.Fprintf(os.Stderr, "cleanup-host: %v\n", err)
		return 1
	}
	return 0
}
