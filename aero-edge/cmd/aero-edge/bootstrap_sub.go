// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	"github.com/aero-protocol/aero-edge/internal/certpin"
	"github.com/aero-protocol/aero-edge/internal/datapath"
	"github.com/aero-protocol/aero-edge/internal/subscribe"
)

func bootstrapDataDirOnly(dataDirFlag string) (string, error) {
	return datapath.Resolve(dataDirFlag)
}

// bootstrapSubscription 固定数据目录、写 sub_meta + client-sub、返回 store
func bootstrapSubscription(dataDirFlag, advertiseHost string, tlsPort int, token, sni string, cert *tls.Certificate) (*subscribe.Store, string, error) {
	dir, err := datapath.Resolve(dataDirFlag)
	if err != nil {
		return nil, "", err
	}
	store, err := subscribe.NewStore(dir)
	if err != nil {
		return nil, "", err
	}

	host := strings.TrimSpace(advertiseHost)
	if host == "" || host == "cdn-aero.com" || host == "localhost" {
		host = "127.0.0.1"
	}
	if tlsPort <= 0 {
		tlsPort = 443
	}
	addr := fmt.Sprintf("%s:%d", host, tlsPort)

	var pins []string
	if cert != nil {
		if pin, err := certpin.FromTLS(cert); err == nil && pin != "" {
			pins = []string{pin}
			log.Printf("[SUB] SPKI pin=%s", pin)
		} else if err != nil {
			log.Printf("[SUB] pin extract: %v", err)
		}
	}

	if err := store.Ensure(subscribe.EnsureParams{
		Name:    "default",
		Address: addr,
		Token:   token,
		SNI:     sni,
		PinSPKI: pins,
	}); err != nil {
		return nil, "", err
	}
	return store, dir, nil
}
