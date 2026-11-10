package edge

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// C3 用户 token（api/token.md）：aero1.<payload>.<signature>，Ed25519 签名覆盖
// "aero1." + payload 的原始字节，校验方先验签再解析，无需 JSON 规范化。

const (
	tokenPrefix      = "aero1."
	tokenMaxLen      = 2048
	tokenMaxLifetime = 7 * 24 * time.Hour
	tokenIatSkew     = 300 * time.Second // 只容忍签发方时钟略快，不放宽 exp
)

var (
	// ErrTokenInvalid 对应 EDGE_AUTH_INVALID_TOKEN（格式、签名或载荷不合规）。
	ErrTokenInvalid = errors.New("EDGE_AUTH_INVALID_TOKEN")
	// ErrTokenExpired 对应 EDGE_AUTH_TOKEN_EXPIRED（已过期或签发时间在未来）。
	ErrTokenExpired = errors.New("EDGE_AUTH_TOKEN_EXPIRED")
)

// TokenClaims 是 token 载荷（字段与 api/token.schema.json 一致，由契约一致性测试守护）。
type TokenClaims struct {
	V          int      `json:"v"`
	Iss        string   `json:"iss"`
	Kid        string   `json:"kid"`
	UID        string   `json:"uid"`
	JTI        string   `json:"jti"`
	Tier       string   `json:"tier"`
	Classes    []string `json:"classes"`
	MaxDevices int      `json:"max_devices"`
	QuotaBytes int64    `json:"quota_bytes,omitempty"`
	BWBps      int64    `json:"bw_bps,omitempty"`
	Iat        int64    `json:"iat"`
	Exp        int64    `json:"exp"`
}

// IssuerKey 是某个 kid 对应的签发方与公钥。
type IssuerKey struct {
	Issuer    string // "sub" 或 "edge"
	PublicKey ed25519.PublicKey
}

// TokenVerifier 按 api/token.md §3 第 1–4 步校验 token。吊销、场景与设备数（第 5–7 步）
// 依赖请求上下文，由调用方执行。
type TokenVerifier struct {
	keys map[string]IssuerKey
	now  func() time.Time
}

// NewTokenVerifier 以 kid → 签发方公钥构建校验器。
func NewTokenVerifier(keys map[string]IssuerKey) *TokenVerifier {
	return &TokenVerifier{keys: keys, now: time.Now}
}

var (
	kidPattern  = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	uidPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	jtiPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	tierPattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	knownClass  = map[string]bool{"default": true, "ai": true, "browser": true, "game": true}
)

// Verify 校验 token 并返回载荷。
func (v *TokenVerifier) Verify(token string) (*TokenClaims, error) {
	// 1. 格式
	if len(token) > tokenMaxLen || !strings.HasPrefix(token, tokenPrefix) {
		return nil, ErrTokenInvalid
	}
	dot := strings.LastIndexByte(token, '.')
	if dot <= len(tokenPrefix) {
		return nil, ErrTokenInvalid
	}
	signingInput, sigPart := token[:dot], token[dot+1:]
	payload, err := base64.RawURLEncoding.DecodeString(signingInput[len(tokenPrefix):])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrTokenInvalid
	}

	// 2. kid → 公钥（kid 必须属于载荷声明的 iss），验签后才信任载荷内容
	var head struct {
		Kid string `json:"kid"`
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &head) != nil {
		return nil, ErrTokenInvalid
	}
	key, ok := v.keys[head.Kid]
	if !ok || key.Issuer != head.Iss || !ed25519.Verify(key.PublicKey, []byte(signingInput), sig) {
		return nil, ErrTokenInvalid
	}

	// 3. 载荷规则
	var c TokenClaims
	if err := json.Unmarshal(payload, &c); err != nil || !claimsWellFormed(&c) {
		return nil, ErrTokenInvalid
	}

	// 4. 时间
	now := v.now()
	if time.Unix(c.Iat, 0).After(now.Add(tokenIatSkew)) || !now.Before(time.Unix(c.Exp, 0)) {
		return nil, ErrTokenExpired
	}
	return &c, nil
}

func claimsWellFormed(c *TokenClaims) bool {
	if c.V != 1 || (c.Iss != "sub" && c.Iss != "edge") || !kidPattern.MatchString(c.Kid) ||
		!uidPattern.MatchString(c.UID) || !jtiPattern.MatchString(c.JTI) || !tierPattern.MatchString(c.Tier) ||
		c.MaxDevices < 1 || c.MaxDevices > 64 || c.QuotaBytes < 0 || c.BWBps < 0 ||
		c.Iat < 0 || c.Exp <= c.Iat || time.Duration(c.Exp-c.Iat)*time.Second > tokenMaxLifetime {
		return false
	}
	if len(c.Classes) == 0 {
		return false
	}
	seen := make(map[string]bool, len(c.Classes))
	for _, cl := range c.Classes {
		if !knownClass[cl] || seen[cl] {
			return false
		}
		seen[cl] = true
	}
	return true
}

// SignToken 签发 token（edge 本地签发 iss=edge 与测试使用；sub 有自己的实现）。
func SignToken(priv ed25519.PrivateKey, c TokenClaims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal token claims: %w", err)
	}
	signingInput := tokenPrefix + base64.RawURLEncoding.EncodeToString(payload)
	if len(signingInput)+1+base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) > tokenMaxLen {
		return "", fmt.Errorf("token exceeds %d bytes", tokenMaxLen)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signingInput))), nil
}
