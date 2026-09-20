// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// HostMetrics is a resource snapshot from SSH probe.
type HostMetrics struct {
	CPUPercent  float64   `json:"cpu_percent"`
	MemTotalMB  float64   `json:"mem_total_mb"`
	MemUsedMB   float64   `json:"mem_used_mb"`
	MemPercent  float64   `json:"mem_percent"`
	DiskTotalGB float64   `json:"disk_total_gb"`
	DiskUsedGB  float64   `json:"disk_used_gb"`
	DiskPercent float64   `json:"disk_percent"`
	Load1       float64   `json:"load_1"`
	Load5       float64   `json:"load_5"`
	Load15      float64   `json:"load_15"`
	NetRxMbps   float64   `json:"net_rx_mbps"`
	NetTxMbps   float64   `json:"net_tx_mbps"`
	UptimeSec   int64     `json:"uptime_sec"`
	OS          string    `json:"os,omitempty"`
	Arch        string    `json:"arch,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
	Source      string    `json:"source"`
	ProbeOK     bool      `json:"probe_ok"`
	ProbeError  string    `json:"probe_error,omitempty"`
	LatencyMS   int64     `json:"latency_ms,omitempty"`
}

// VPSHost is a machine asset managed by the platform.
type VPSHost struct {
	ID                uint64       `json:"id"`
	Name              string       `json:"name"`
	Role              string       `json:"role"`
	IP                string       `json:"ip"`
	SSHPort           int          `json:"ssh_port"`
	SSHUsername       string       `json:"ssh_username"`
	HasPassword       bool         `json:"has_password"`
	Domain            string       `json:"domain,omitempty"`
	Remark            string       `json:"remark,omitempty"`
	Status            string       `json:"status"` // registered | online | offline | error
	HealthScore       int          `json:"health_score"`
	Tier              int          `json:"tier"` // 1: Nano/Edge (<=1G), 2: Standard (<=4G), 3: Enterprise (>4G)
	CapacityState     string       `json:"capacity_state"`
	PurityScore       int          `json:"purity_score"` // 0~100 出口纯净度软评分 (Google 60 + CF 40)
	AIBlocked         bool         `json:"ai_blocked"`   // 遭遇 AI 封锁一票否决
	GoogleClean       bool         `json:"google_clean"` // Google 打靶正常 (无 429)
	CFClean           bool         `json:"cf_clean"`     // Cloudflare 打靶正常
	IsWARPEgress      bool         `json:"is_warp_egress"`
	Metrics           *HostMetrics `json:"metrics,omitempty"`
	LastProbeAt       *time.Time   `json:"last_probe_at,omitempty"`
	LastPurityProbeAt *time.Time   `json:"last_purity_probe_at,omitempty"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// PurityResult 目标 VPS 出口纯净度远程打靶快照
type PurityResult struct {
	VPSID        uint64    `json:"vps_id"`
	PurityScore  int       `json:"purity_score"`
	AIBlocked    bool      `json:"ai_blocked"`
	GoogleClean  bool      `json:"google_clean"`
	CFClean      bool      `json:"cf_clean"`
	IsWARPEgress bool      `json:"is_warp_egress"`
	RawOutput    string    `json:"raw_output,omitempty"`
	ProbeAt      time.Time `json:"probe_at"`
	ProbeError   string    `json:"probe_error,omitempty"`
}

// UpdateVPSParams defines mutable metadata for VPS.
type UpdateVPSParams struct {
	Name        string `json:"name,omitempty"`
	Role        string `json:"role,omitempty"`
	SSHPort     int    `json:"ssh_port,omitempty"`
	SSHUsername string `json:"ssh_username,omitempty"`
	Remark      string `json:"remark,omitempty"`
}

// CreateVPSParams registration input.
type CreateVPSParams struct {
	Name        string
	Role        string
	IP          string
	SSHPort     int
	SSHUsername string
	SSHPassword string
	Domain      string
	Remark      string
}

// Credentials is SSH material for internal callers.
type Credentials struct {
	VPSID       uint64 `json:"vps_id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	SSHPort     int    `json:"ssh_port"`
	SSHUsername string `json:"ssh_username"`
	SSHPassword string `json:"ssh_password"`
	Domain      string `json:"domain,omitempty"`
}

// SecretBox provides AES-256-GCM encryption for credentials.
type SecretBox struct {
	gcm cipher.AEAD
}

// NewSecretBox derives a 32-byte key from env SSH_CRED_KEY or HMAC_SECRET.
func NewSecretBox() (*SecretBox, error) {
	raw := strings.TrimSpace(os.Getenv("SSH_CRED_KEY"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("HMAC_SECRET"))
	}
	if raw == "" {
		raw = "dev-ssh-cred-key-change-me"
	}
	sum := sha256.Sum256([]byte(raw))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{gcm: gcm}, nil
}

// Encrypt returns base64(nonce|ciphertext). Empty input → empty output.
func (b *SecretBox) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if b == nil || b.gcm == nil {
		return "", errors.New("crypto box not initialized")
	}
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := b.gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt reverses Encrypt.
func (b *SecretBox) Decrypt(blob string) (string, error) {
	if blob == "" {
		return "", nil
	}
	if b == nil || b.gcm == nil {
		return "", errors.New("crypto box not initialized")
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext: %w", err)
	}
	ns := b.gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	plain, err := b.gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed: %w", err)
	}
	return string(plain), nil
}
