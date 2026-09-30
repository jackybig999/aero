// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/aero-protocol/aero/internal/edge"
)

func isPortAvailable(addr string) bool {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func autoProbePort(preferred string) string {
	if preferred != "" && preferred != ":auto" && isPortAvailable(preferred) {
		return preferred
	}
	// Candidate standard HTTPS ports in priority order (Cloudflare & IANA standard HTTPS ports)
	for _, port := range []int{443, 8443, 2053, 2083, 2087, 2096} {
		cand := fmt.Sprintf(":%d", port)
		if isPortAvailable(cand) {
			if preferred != "" && preferred != ":auto" {
				log.Printf("[PORT] Preferred port %s is occupied; auto-selected candidate HTTPS port: %s", preferred, cand)
			}
			return cand
		}
	}
	if preferred != "" && preferred != ":auto" {
		return preferred
	}
	return ":443"
}

func main() {
	showVer := flag.Bool("version", false, "print version and exit")
	listen := flag.String("listen", ":443", "listen address (e.g. :443)")
	ports := flag.String("ports", "", "listen ports (legacy compat, e.g. 443)")
	domain := flag.String("domain", "", "public domain or SNI")
	sni := flag.String("sni", "", "server SNI (legacy compat)")
	token := flag.String("token", "", "initial bootstrap token (auto-generated if empty)")
	certFile := flag.String("cert", "", "path to TLS cert PEM")
	keyFile := flag.String("key", "", "path to TLS key PEM")
	autoCert := flag.String("autocert", "", "Let's Encrypt / auto cert domain (legacy compat)")
	autoCertDir := flag.String("auto-cert-dir", "./certs", "auto cert directory (legacy compat)")
	dataDir := flag.String("data-dir", "./data", "data directory for tokens.json and client-sub.json")
	adminKey := flag.String("admin-key", "", "remote Admin API key (X-Aero-Admin-Key)")
	profile := flag.String("profile", "small", "performance profile: tiny|small|medium")
	maxConn := flag.Int("max-conn", 0, "max active tunnels global (0=default)")
	maxConnUser := flag.Int("max-conn-user", 0, "max active tunnels per user token (0=default)")
	rateIP := flag.Int("rate-ip", 0, "max incoming connections/s/IP (0=default)")
	bwUser := flag.Int("bw-user", 0, "max bandwidth bytes/s per user (0=unlimited)")
	advHost := flag.String("advertise-host", "", "public advertise host in subscription")
	coverName := flag.String("cover-name", "CloudEdge CDN", "cover site title")
	logFile := flag.String("log-file", "", "path to edge log file")
	quiet := flag.Bool("q", false, "quiet mode (suppress verbose logs)")
	configPath := flag.String("config", "", "path to JSON configuration file")

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

	// Logging configuration
	if *logFile != "" {
		if err := os.MkdirAll(filepath.Dir(*logFile), 0755); err == nil {
			if f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				if *quiet {
					log.SetOutput(f)
				} else {
					log.SetOutput(io.MultiWriter(os.Stderr, f))
				}
			}
		}
	} else if *quiet {
		log.SetOutput(io.Discard)
	}

	// Legacy flag mapping
	if *domain == "" && *sni != "" {
		*domain = *sni
	}
	if *domain == "" && *autoCert != "" {
		*domain = *autoCert
	}
	_ = autoCertDir

	if *ports != "" && (*listen == ":443" || *listen == "") {
		p := strings.TrimSpace(*ports)
		if !strings.HasPrefix(p, ":") {
			p = ":" + p
		}
		*listen = p
	}

	// Dynamic port probing if preferred port is occupied
	*listen = autoProbePort(*listen)

	cfg := edge.ServerConfig{
		Listen:        *listen,
		Domain:        *domain,
		Token:         *token,
		CertFile:      *certFile,
		KeyFile:       *keyFile,
		DataDir:       *dataDir,
		AdminKey:      *adminKey,
		Profile:       *profile,
		MaxConn:       *maxConn,
		MaxConnUser:   *maxConnUser,
		RateIP:        *rateIP,
		BWUser:        *bwUser,
		AdvertiseHost: *advHost,
		CoverName:     *coverName,
	}

	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			log.Fatalf("failed to read config file %s: %v", *configPath, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("failed to parse config file %s: %v", *configPath, err)
		}
		log.Printf("[CONFIG] loaded configuration from %s", *configPath)
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
