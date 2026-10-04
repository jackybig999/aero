// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	obfsFallbackRegistryMu sync.RWMutex
	obfsFallbackRegistry   = make(map[string][]string)
)

// RegisterFallbackPasswords associates fallback obfuscation passwords with a primary password.
func RegisterFallbackPasswords(primaryPassword string, fallbackPasswords []string) {
	obfsFallbackRegistryMu.Lock()
	defer obfsFallbackRegistryMu.Unlock()
	if len(fallbackPasswords) == 0 {
		delete(obfsFallbackRegistry, primaryPassword)
	} else {
		obfsFallbackRegistry[primaryPassword] = append([]string(nil), fallbackPasswords...)
	}
}

// SalamanderPacketConn implements UDP obfuscation using Blake2b key derivation,
// ChaCha20 stream cipher, random salt, and dynamic padding jitter.
type SalamanderPacketConn struct {
	net.PacketConn
	password      []byte
	fallbackKeys  [][]byte
	paddingJitter bool
	mu            sync.RWMutex
}

// NewSalamanderPacketConn creates a new SalamanderPacketConn.
func NewSalamanderPacketConn(pconn net.PacketConn, password string, paddingJitter bool, fallbackPasswords ...string) *SalamanderPacketConn {
	c := &SalamanderPacketConn{
		PacketConn:    pconn,
		password:      []byte(password),
		paddingJitter: paddingJitter,
	}
	if len(fallbackPasswords) > 0 {
		c.SetFallbackPasswords(fallbackPasswords)
	} else if password != "" {
		obfsFallbackRegistryMu.RLock()
		if fbs, ok := obfsFallbackRegistry[password]; ok && len(fbs) > 0 {
			c.SetFallbackPasswords(fbs)
		}
		obfsFallbackRegistryMu.RUnlock()
	}
	return c
}

// SetFallbackPasswords sets the fallback obfuscation passwords for key rollover.
func (c *SalamanderPacketConn) SetFallbackPasswords(passwords []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fallbackKeys = make([][]byte, 0, len(passwords))
	for _, p := range passwords {
		if p != "" {
			c.fallbackKeys = append(c.fallbackKeys, []byte(p))
		}
	}
}

// FallbackKeys returns a copy of the fallback keys.
func (c *SalamanderPacketConn) FallbackKeys() [][]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res := make([][]byte, len(c.fallbackKeys))
	for i, k := range c.fallbackKeys {
		res[i] = append([]byte(nil), k...)
	}
	return res
}

// WriteTo encrypts and obfuscates datagram b, sending it to addr.
// 100% 采用 primary password 加密。
func (c *SalamanderPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(c.password) == 0 {
		return c.PacketConn.WriteTo(b, addr)
	}

	// 8 字节密码学强随机盐
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return 0, err
	}

	// 确定目标混淆后长度 targetLen
	// 线路开销：8字节salt + 16字节Poly1305 tag + 2字节origLen = 26字节基础开销
	var targetLen int
	minOverhead := 8 + 16 + 2
	if c.paddingJitter {
		n, err := rand.Int(rand.Reader, big.NewInt(101)) // [0, 100] -> [1280, 1380]
		if err != nil {
			return 0, err
		}
		targetLen = 1280 + int(n.Int64())
		if minOverhead+len(b) > targetLen {
			targetLen = minOverhead + len(b)
		}
	} else {
		targetLen = minOverhead + len(b)
	}

	// 组织明文 payload：
	// 前 2 字节为原始长度 uint16，随后追加原始数据 b，若 targetLen > 24 + len(b)，剩余空间填充 crypto/rand 强随机数
	// 因为 salt 占 8 字节，tag 占 16 字节，两者共 24 字节在线路开销中
	plaintextLen := targetLen - 24
	plaintext := make([]byte, plaintextLen)
	binary.BigEndian.PutUint16(plaintext[:2], uint16(len(b)))
	copy(plaintext[2:2+len(b)], b)
	if plaintextLen > 2+len(b) {
		if _, err := io.ReadFull(rand.Reader, plaintext[2+len(b):]); err != nil {
			return 0, err
		}
	}

	// 密钥衍生与 AEAD 流加密：
	keyMaterial := make([]byte, len(c.password)+8)
	copy(keyMaterial, c.password)
	copy(keyMaterial[len(c.password):], salt)
	key := blake2b.Sum256(keyMaterial)

	// nonce := make([]byte, chacha20poly1305.NonceSize); copy(nonce, salt) (12 字节 nonce)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, salt)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return 0, err
	}

	// Seal 会将 16 字节 Poly1305 认证标签自动追加到密文尾部
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// 最终线路上发送的数据报为：append(salt, ciphertext...)
	wireBytes := make([]byte, 8+len(ciphertext))
	copy(wireBytes[:8], salt)
	copy(wireBytes[8:], ciphertext)

	// 写入底层 c.PacketConn.WriteTo(wireBytes, addr)，返回值返回 len(b) 保证上层协议无感知！
	if _, err := c.PacketConn.WriteTo(wireBytes, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}

func tryDecrypt(key, salt, ciphertext, b []byte) (int, bool) {
	if len(ciphertext) < 16+2 { // 必须包含 16 字节 Poly1305 Tag + 至少 2 字节原长
		return 0, false
	}
	keyMaterial := make([]byte, len(key)+8)
	copy(keyMaterial, key)
	copy(keyMaterial[len(key):], salt)
	derivedKey := blake2b.Sum256(keyMaterial)

	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, salt)

	aead, err := chacha20poly1305.New(derivedKey[:])
	if err != nil {
		return 0, false
	}

	// Open 执行 ChaCha20 解密并严格校验 Poly1305 MAC 认证标签
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, false // 密文被篡改或密钥错误，立即静默丢弃
	}

	if len(plaintext) < 2 {
		return 0, false
	}
	origLen := binary.BigEndian.Uint16(plaintext[:2])
	// 若 int(origLen) > len(plaintext)-2，数据损坏/长度不合法
	if int(origLen) == 0 || int(origLen) > len(plaintext)-2 {
		return 0, false
	}

	copyLen := int(origLen)
	if copyLen > len(b) {
		copyLen = len(b)
	}
	copy(b, plaintext[2:2+copyLen])
	return copyLen, true
}

// ReadFrom reads an obfuscated datagram from the wire, decrypts it, and returns the original payload.
func (c *SalamanderPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(c.password) == 0 {
		return c.PacketConn.ReadFrom(b)
	}

	buf := make([]byte, 65535)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}

		// 长度校验：若 n < 26 (8 字节 salt + 2 字节 uint16 长度 + 16 字节 Poly1305 tag)，丢弃
		if n < 26 {
			continue
		}

		salt := buf[:8]
		ciphertext := buf[8:n]

		// 1. 优先使用 primary password 解密
		if copyLen, ok := tryDecrypt(c.password, salt, ciphertext, b); ok {
			return copyLen, addr, nil
		}

		// 2. 若解密失败（检验 origLen > len(plaintext)-2），自动遍历 fallbackKeys 逐一尝试；匹配则成功解密返回
		c.mu.RLock()
		fallbacks := c.fallbackKeys
		var matchedLen int
		matched := false
		for _, fbKey := range fallbacks {
			if copyLen, ok := tryDecrypt(fbKey, salt, ciphertext, b); ok {
				matchedLen = copyLen
				matched = true
				break
			}
		}
		c.mu.RUnlock()

		if matched {
			return matchedLen, addr, nil
		}

		// 未授权密钥或解密全部失败，静默丢弃
	}
}

// SetReadBuffer sets the read buffer size on the underlying packet conn if supported.
func (c *SalamanderPacketConn) SetReadBuffer(bytes int) error {
	if sc, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return sc.SetReadBuffer(bytes)
	}
	return nil
}

// SetWriteBuffer sets the write buffer size on the underlying packet conn if supported.
func (c *SalamanderPacketConn) SetWriteBuffer(bytes int) error {
	if sc, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return sc.SetWriteBuffer(bytes)
	}
	return nil
}
