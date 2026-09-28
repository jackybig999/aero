// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package sub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// signBody 与 Edge subscribe.Sign 使用相同字段顺序与 omitempty 规则
type signBody struct {
	Version   string         `json:"version"`
	UserID    string         `json:"userId,omitempty"`
	ExpireAt  int64          `json:"expireAt,omitempty"`
	Servers   []ServerConfig `json:"servers"`
	CreatedAt int64          `json:"createdAt,omitempty"`
}

// Sign 签名（key 通常为节点 token）
func Sign(sub *Subscription, key []byte) string {
	if sub == nil {
		return ""
	}
	body := signBody{
		Version:   sub.Version,
		UserID:    sub.UserID,
		ExpireAt:  sub.ExpireAt,
		Servers:   sub.Servers,
		CreatedAt: sub.CreatedAt,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify 校验签名
func Verify(sub *Subscription, key []byte) bool {
	if sub == nil || sub.Signature == "" || len(key) == 0 {
		return false
	}
	expected := Sign(sub, key)
	return hmac.Equal([]byte(expected), []byte(sub.Signature))
}
