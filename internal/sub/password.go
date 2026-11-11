package sub

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// 密码哈希：argon2id（OWASP 推荐的最低参数：19 MiB、2 轮、1 并行）。不取更大内存：小 VPS 上
// 并发登录会被放大成内存耗尽。旧格式 "sha256:<salt>:<hex>"（单轮 SHA-256）仍可校验，登录成功后
// 由 Login 自动重新哈希为当前格式。
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	argonSaltLen   = 16
	argonPrefix    = "argon2id$"
)

var argonParams = fmt.Sprintf("v=%d$m=%d,t=%d,p=%d", argon2.Version, argonMemoryKiB, argonTime, argonThreads)

// HashPassword 返回 argon2id 哈希："argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>"（base64 无填充）。
func HashPassword(password string) string {
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt) // Go 1.24 起 crypto/rand.Read 不会返回错误（失败时进程终止）
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return argonPrefix + argonParams + "$" + enc.EncodeToString(salt) + "$" + enc.EncodeToString(key)
}

// CheckPassword 以恒定时间比较校验密码，支持当前 argon2id 格式（任意参数）与旧 sha256 格式。
func CheckPassword(password, stored string) bool {
	switch {
	case strings.HasPrefix(stored, argonPrefix):
		return checkArgon2id(password, stored)
	case strings.HasPrefix(stored, "sha256:"):
		return checkLegacySHA256(password, stored)
	}
	return false
}

// passwordNeedsRehash 报告存储的哈希是否为旧格式或旧参数，需要在下次登录成功时重新哈希。
func passwordNeedsRehash(stored string) bool {
	return !strings.HasPrefix(stored, argonPrefix+argonParams+"$")
}

func checkArgon2id(password, stored string) bool {
	// argon2id$v=19$m=..,t=..,p=..$salt$key
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[1] != fmt.Sprintf("v=%d", argon2.Version) {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || m > 1<<20 || t == 0 || t > 16 || p == 0 {
		return false // 拒绝异常参数，防止被构造成内存或 CPU 炸弹
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[3])
	if err != nil || len(salt) < 8 {
		return false
	}
	key, err := enc.DecodeString(parts[4])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1
}

func checkLegacySHA256(password, stored string) bool {
	rest := strings.TrimPrefix(stored, "sha256:")
	salt, hash, ok := strings.Cut(rest, ":")
	if !ok || salt == "" || len(hash) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(salt + password))
	return subtle.ConstantTimeCompare([]byte(hash), []byte(fmt.Sprintf("%x", h))) == 1
}

// dummyPasswordHash 用于用户不存在时执行同等开销的比较，使响应时间不泄露用户名是否存在。
var dummyPasswordHash = HashPassword("aero-dummy-password-for-timing")
