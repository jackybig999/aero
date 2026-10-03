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

	"github.com/aero-protocol/aero/aeroprot/internal/edge"
)

func main() {
	showVer := flag.Bool("version", false, "print version and exit")
	listen := flag.String("listen", ":443", "listen address (e.g. :443)")
	domain := flag.String("domain", "", "public domain or SNI")
	token := flag.String("token", "", "initial bootstrap token (auto-generated if empty)")
	certFile := flag.String("cert", "", "path to TLS cert PEM")
	keyFile := flag.String("key", "", "path to TLS key PEM")
	dataDir := flag.String("data-dir", "./data", "data directory for tokens.json and client-sub.json")
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
