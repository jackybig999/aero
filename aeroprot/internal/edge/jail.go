// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"sync"
	"time"
)

type jailEntry struct {
	failures   int
	firstFail  time.Time
	banUntil   time.Time
	lastActive time.Time
}

// AuthFailureJail tracks failed authentications and bans abusing IPs.
type AuthFailureJail struct {
	mu      sync.RWMutex
	records map[string]*jailEntry
	stopCh  chan struct{}
}

// NewAuthFailureJail creates and starts a new AuthFailureJail.
func NewAuthFailureJail() *AuthFailureJail {
	j := &AuthFailureJail{
		records: make(map[string]*jailEntry),
		stopCh:  make(chan struct{}),
	}
	go j.cleanupLoop()
	return j
}

// RecordFailure records an authentication failure for ip.
// If an IP fails 5 times within 1 minute, it is banned for 15 minutes.
// Returns true if the IP is currently banned.
func (j *AuthFailureJail) RecordFailure(ip string) bool {
	if ip == "" {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()
	entry, ok := j.records[ip]
	if !ok {
		j.records[ip] = &jailEntry{
			failures:   1,
			firstFail:  now,
			lastActive: now,
		}
		return false
	}

	entry.lastActive = now

	// If already banned and ban has not expired
	if now.Before(entry.banUntil) {
		return true
	}

	// If previous failure window expired (> 1 minute), reset window
	if now.Sub(entry.firstFail) > time.Minute {
		entry.failures = 1
		entry.firstFail = now
		return false
	}

	entry.failures++
	if entry.failures >= 5 {
		entry.banUntil = now.Add(15 * time.Minute)
		return true
	}

	return false
}

// IsBanned returns true if the IP is currently banned.
func (j *AuthFailureJail) IsBanned(ip string) bool {
	if ip == "" {
		return false
	}
	j.mu.RLock()
	defer j.mu.RUnlock()

	entry, ok := j.records[ip]
	if !ok {
		return false
	}
	return time.Now().Before(entry.banUntil)
}

// cleanupLoop periodically sweeps stale and expired entries every 3 minutes.
func (j *AuthFailureJail) cleanupLoop() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-j.stopCh:
			return
		case <-ticker.C:
			j.mu.Lock()
			now := time.Now()
			for ip, entry := range j.records {
				if now.After(entry.banUntil) && now.Sub(entry.lastActive) > 10*time.Minute {
					delete(j.records, ip)
				}
			}
			j.mu.Unlock()
		}
	}
}

// Close gracefully stops the cleanup loop.
func (j *AuthFailureJail) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	select {
	case <-j.stopCh:
	default:
		close(j.stopCh)
	}
}
