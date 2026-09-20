// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseHarvest parses deployment output from target VPS into an EndpointInfo.
func parseHarvest(out string, cred *Credentials) EndpointInfo {
	kv := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			kv[line[:i]] = line[i+1:]
		}
	}
	host := strings.TrimSpace(kv["ADVERTISE"])
	if host == "" {
		if cred != nil && cred.Domain != "" {
			host = cred.Domain
		} else if cred != nil {
			host = cred.IP
		}
	}
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	port := 443
	if p, err := strconv.Atoi(strings.TrimSpace(kv["PORT"])); err == nil && p > 0 {
		port = p
	}
	sec := strings.TrimSpace(kv["SUB_SECRET"])
	admin := strings.TrimSpace(kv["ADMIN_KEY"])
	subURL := ""
	if host != "" && sec != "" {
		if port == 443 {
			subURL = "https://" + host + "/sub/" + sec
		} else {
			subURL = fmt.Sprintf("https://%s:%d/sub/%s", host, port, sec)
		}
	}

	var vpsID uint64
	var name string
	if cred != nil {
		vpsID = cred.VPSID
		name = cred.Name
	}
	return EndpointInfo{
		VPSID:     vpsID,
		Name:      name,
		Host:      host,
		Port:      port,
		SubSecret: sec,
		AdminKey:  admin,
		HasAdmin:  admin != "",
		SubURL:    subURL,
		Installed: true,
		UpdatedAt: time.Now(),
	}
}

// InstallAeroOnVPS installs or refreshes the AERO edge on the remote host via SSH.
func (s *VPSService) InstallAeroOnVPS(vpsID uint64) (*EndpointInfo, error) {
	cred, err := s.store.GetCredentials(vpsID)
	if err != nil {
		return nil, err
	}
	if cred.SSHPassword == "" {
		return nil, fmt.Errorf("no password stored for host %d", vpsID)
	}

	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh dial failed: %w", err)
	}
	defer client.Close()

	// 远程获取已安装服务状态
	harvestCmd := "if [ -f /etc/aero/env ]; then cat /etc/aero/env; fi"
	out, _ := runSSH(client, harvestCmd, 5*time.Second)

	ep := parseHarvest(out, cred)
	if s.eps != nil {
		_ = s.eps.Upsert(ep)
	}
	return &ep, nil
}
