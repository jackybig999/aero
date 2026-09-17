// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package subscribe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// 与 aero-ech/internal/sub.signBody 字段一致
type signBody struct {
	Version   string   `json:"version"`
	UserID    string   `json:"userId,omitempty"`
	ExpireAt  int64    `json:"expireAt,omitempty"`
	Servers   []Server `json:"servers"`
	CreatedAt int64    `json:"createdAt,omitempty"`
}

// Sign 用 key（通常为 token）签名
func Sign(doc Document, key []byte) string {
	body := signBody{
		Version:   doc.Version,
		UserID:    doc.UserID,
		ExpireAt:  doc.ExpireAt,
		Servers:   doc.Servers,
		CreatedAt: doc.CreatedAt,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify 校验
func Verify(doc Document, key []byte) bool {
	if doc.Signature == "" || len(key) == 0 {
		return false
	}
	expected := Sign(doc, key)
	return hmac.Equal([]byte(expected), []byte(doc.Signature))
}
