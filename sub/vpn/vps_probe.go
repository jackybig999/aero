// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHCredentials encapsulates parameters to dial a target machine.
type SSHCredentials struct {
	Host     string
	Port     int
	User     string
	Password string
}

func dialSSH(c SSHCredentials, timeout time.Duration) (*ssh.Client, error) {
	if c.Port <= 0 {
		c.Port = 22
	}
	if c.User == "" {
		c.User = "root"
	}
	if c.Password == "" {
		return nil, fmt.Errorf("SSH password empty")
	}
	pass := c.Password
	auth := []ssh.AuthMethod{
		ssh.Password(pass),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			ans := make([]string, len(questions))
			for i := range questions {
				ans[i] = pass
			}
			return ans, nil
		}),
	}
	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	return ssh.Dial("tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), cfg)
}

func runSSH(client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	ch := make(chan struct {
		out []byte
		err error
	}, 1)

	go func() {
		b, err := sess.CombinedOutput(cmd)
		ch <- struct {
			out []byte
			err error
		}{b, err}
	}()

	select {
	case res := <-ch:
		return string(res.out), res.err
	case <-time.After(timeout):
		_ = sess.Signal(ssh.SIGKILL)
		return "", fmt.Errorf("ssh command timeout after %v", timeout)
	}
}

// EvaluatePurity parses probe command output into a PurityResult.
func EvaluatePurity(rawOutput string, vpsID uint64) PurityResult {
	res := PurityResult{
		VPSID:       vpsID,
		RawOutput:   strings.TrimSpace(rawOutput),
		ProbeAt:     time.Now(),
		PurityScore: 0,
	}

	parts := strings.Split(res.RawOutput, ",")
	gCode, cfCode, aiCode, warpOn := "000", "000", "000", "0"
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "G":
				gCode = kv[1]
			case "CF":
				cfCode = kv[1]
			case "AI":
				aiCode = kv[1]
			case "WARP":
				warpOn = kv[1]
			}
		}
	}

	// 1. 硬门禁判定：AI 阻断一票否决
	if aiCode == "403" || aiCode == "429" || aiCode == "000" {
		res.AIBlocked = true
	} else {
		res.AIBlocked = false
	}

	// 2. 软评分判定：Google (60 分) + Cloudflare (40 分)
	if gCode == "200" {
		res.GoogleClean = true
		res.PurityScore += 60
	}
	if cfCode == "200" {
		res.CFClean = true
		res.PurityScore += 40
	}
	res.IsWARPEgress = (warpOn == "1")

	return res
}

// ProbePurity executes remote probe from target VPS egress IP.
func (s *VPSService) ProbePurity(ctx context.Context, id uint64) (*PurityResult, error) {
	cred, err := s.store.GetCredentials(id)
	if err != nil {
		return nil, err
	}
	if cred.SSHPassword == "" {
		return nil, fmt.Errorf("no password stored for host %d", id)
	}

	client, err := dialSSH(SSHCredentials{
		Host: cred.IP, Port: cred.SSHPort, User: cred.SSHUsername, Password: cred.SSHPassword,
	}, 6*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ssh dial target vps: %w", err)
	}
	defer client.Close()

	cmd := `g_code=$(curl -s -m 4 -o /dev/null -w "%{http_code}" "https://www.google.com/search?q=aero_probe" 2>/dev/null || echo "000"); ` +
		`cf_code=$(curl -s -m 4 -o /dev/null -w "%{http_code}" "https://cloudflare.com/cdn-cgi/trace" 2>/dev/null || echo "000"); ` +
		`ai_code=$(curl -s -m 4 -o /dev/null -w "%{http_code}" "https://api.anthropic.com/api/hello" 2>/dev/null || echo "000"); ` +
		`warp_on=$(ip a 2>/dev/null | grep -q "warp" && echo "1" || echo "0"); ` +
		`echo "G:$g_code,CF:$cf_code,AI:$ai_code,WARP:$warp_on"`

	out, err := runSSH(client, cmd, 8*time.Second)
	res := EvaluatePurity(out, id)
	if err != nil {
		res.ProbeError = err.Error()
	}

	_ = s.store.UpdatePurity(id, &res)
	return &res, err
}

func (s *VPSService) ProbeAllPurity(ctx context.Context) map[uint64]*PurityResult {
	hosts, err := s.store.List()
	if err != nil {
		return nil
	}
	results := make(map[uint64]*PurityResult)
	var mu sync.Mutex
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, h := range hosts {
		h := h
		if h.IP == "" || h.Status == "error" {
			continue
		}
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				if res, err := s.ProbePurity(ctx, id); err == nil && res != nil {
					mu.Lock()
					results[id] = res
					mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}(h.ID)
	}
	wg.Wait()
	return results
}

func (s *VPSService) StartPurityTicker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 4 * time.Hour
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Printf("[VPS-PURITY] starting scheduled 4h purity probe cycle...")
				_ = s.ProbeAllPurity(ctx)
			}
		}
	}()
}
