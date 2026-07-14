// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
)

// generateToken 生成 32 字节 hex 随机 token
func generateToken() string {
	return auth.GenerateToken()
}

// generateSessionID 生成 8 字节 hex 随机 session ID
func generateSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
