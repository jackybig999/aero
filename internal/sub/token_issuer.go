package sub

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// C3 用户 token 签发（api/token.md，iss=sub）。私钥只在中台数据目录（0600），不出现在订阅、日志或
// 接口响应中；edge 以配置 token_issuers 中的公钥离线验签（ADR-0002）。中台与 edge 是隔离组件，
// 编码按契约各自实现，由 api/testdata/c3-golden.json 黄金向量守护逐字节一致。

const (
	tokenSigningKeyFile = "token-signing.key"
	tokenPrefix         = "aero1."
	tokenTTL            = 24 * time.Hour // C3 §4 推荐有效期；client 在剩余 25% 时刷新
	defaultMaxDevices   = 3
	staffMaxDevices     = 10
)

// allTrafficClasses 是 C3 已知场景；场景授权（第 6 步）由档位参数决定，档位表落地前先全部授权。
var allTrafficClasses = []string{"default", "ai", "browser", "game"}

var issuerKidPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// tokenClaims 的字段与顺序决定签名字节，须与 api/token.schema.json 和黄金向量一致。
type tokenClaims struct {
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

// TokenIssuer 持有中台签发私钥。
type TokenIssuer struct {
	kid  string
	priv ed25519.PrivateKey
	now  func() time.Time
}

type tokenSigningKeyFileFormat struct {
	Kid  string `json:"kid"`
	Seed string `json:"seed"` // base64 的 32 字节 Ed25519 种子
}

// LoadOrCreateTokenIssuer 读取数据目录中的签发密钥；不存在时生成并原子写入（0600）。
func LoadOrCreateTokenIssuer(dataDir string) (*TokenIssuer, error) {
	path := filepath.Join(dataDir, tokenSigningKeyFile)
	b, err := os.ReadFile(path)
	if err == nil {
		var f tokenSigningKeyFileFormat
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		seed, err := base64.StdEncoding.DecodeString(f.Seed)
		if err != nil || len(seed) != ed25519.SeedSize || !issuerKidPattern.MatchString(f.Kid) {
			return nil, fmt.Errorf("invalid token signing key in %s", path)
		}
		return &TokenIssuer{kid: f.Kid, priv: ed25519.NewKeyFromSeed(seed), now: time.Now}, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	suffix, err := randomHex(4)
	if err != nil {
		return nil, err
	}
	f := tokenSigningKeyFileFormat{Kid: "sub-" + suffix, Seed: base64.StdEncoding.EncodeToString(seed)}
	out, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic0600(path, out); err != nil {
		return nil, err
	}
	return &TokenIssuer{kid: f.Kid, priv: ed25519.NewKeyFromSeed(seed), now: time.Now}, nil
}

// Kid 返回签发密钥标识；PublicKeyBase64 返回 edge 配置 token_issuers 所需的公钥（base64）。
func (ti *TokenIssuer) Kid() string { return ti.kid }

func (ti *TokenIssuer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(ti.priv.Public().(ed25519.PublicKey))
}

var errSubscriptionExpired = errors.New("subscription expired")

// IssueForUser 为订阅用户签发 token：exp 取 24 小时与订阅到期中较早者；订阅已过期时拒绝。
// uid 取 user_uuid 加用户 ID：user_uuid 只有 24 位随机数，可能重复，而重复会让两人共享设备名额。
func (ti *TokenIssuer) IssueForUser(u *User) (string, time.Time, error) {
	now := ti.now()
	exp := now.Add(tokenTTL)
	if !u.IsStaff && !u.ExpireAt.IsZero() {
		if !u.ExpireAt.After(now) {
			return "", time.Time{}, errSubscriptionExpired
		}
		if u.ExpireAt.Before(exp) {
			exp = u.ExpireAt
		}
	}
	jti, err := randomBase64URL(16)
	if err != nil {
		return "", time.Time{}, err
	}
	c := tokenClaims{
		V: 1, Iss: "sub", Kid: ti.kid,
		UID: tokenUID(u), JTI: jti,
		Tier: "standard", Classes: allTrafficClasses, MaxDevices: defaultMaxDevices,
		Iat: now.Unix(), Exp: exp.Unix(),
	}
	if u.IsStaff {
		c.Tier, c.MaxDevices = "admin", staffMaxDevices
	}
	tok, err := signToken(ti.priv, c)
	return tok, exp, err
}

// signToken 按 C3 §1 编码：aero1.<base64url(payload)>.<base64url(Ed25519("aero1."+payload))>。
func signToken(priv ed25519.PrivateKey, c tokenClaims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := tokenPrefix + base64.RawURLEncoding.EncodeToString(payload)
	tok := signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signingInput)))
	if len(tok) > 2048 {
		return "", fmt.Errorf("token exceeds 2048 bytes")
	}
	return tok, nil
}

// tokenUID 生成满足 C3 uid 规则（[A-Za-z0-9_-]{8,64}）且按用户唯一的标识。
func tokenUID(u *User) string {
	uid := fmt.Sprintf("%s-%d", sanitizeUID(u.UUID), u.ID)
	if len(uid) < 8 || len(uid) > 64 {
		uid = fmt.Sprintf("user-%08d", u.ID)
	}
	return uid
}

// sanitizeUID 只保留 uid 允许的字符（[A-Za-z0-9_-]），为空时用 "u"。
func sanitizeUID(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "u"
	}
	return string(out)
}

func randomBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// writeFileAtomic0600 以同目录临时文件原子写入（L0 §8.8）。
func writeFileAtomic0600(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Chmod(0o600)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
	}
	return werr
}
