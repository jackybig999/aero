// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"net"
	"sync"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	keyMaterialPool = sync.Pool{New: func() any { b := make([]byte, 128); return &b }}
	wireBufPool     = sync.Pool{New: func() any { b := make([]byte, 2048); return &b }}
	recvBufPool     = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)

// computeJitteredLen 抗 ML-DPI 高斯分布包长抖动 (均值 1320，标准差 25)
func computeJitteredLen(origLen int) int {
	var b [8]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	val := float64(binary.LittleEndian.Uint64(b[:])) / float64(^uint64(0))
	var b2 [8]byte
	_, _ = io.ReadFull(rand.Reader, b2[:])
	val2 := float64(binary.LittleEndian.Uint64(b2[:])) / float64(^uint64(0))
	if val <= 0 {
		val = 0.0001
	}
	// Box-Muller 正态分布变换：均值 1320，标准差 25
	z := math.Sqrt(-2*math.Log(val)) * math.Cos(2*math.Pi*val2)
	target := int(z*25 + 1320)
	if target < 1280 {
		target = 1280
	}
	if target > 1380 {
		target = 1380
	}
	minOverhead := 8 + 16 + 2
	if origLen+minOverhead > target {
		return origLen + minOverhead
	}
	return target
}

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

	minOverhead := 8 + 16 + 2
	var targetLen int
	if c.paddingJitter {
		targetLen = computeJitteredLen(len(b))
		if minOverhead+len(b) > targetLen {
			targetLen = minOverhead + len(b)
		}
	} else {
		targetLen = minOverhead + len(b)
	}

	plaintextLen := targetLen - 24
	ptPtr := wireBufPool.Get().(*[]byte)
	defer wireBufPool.Put(ptPtr)
	if cap(*ptPtr) < plaintextLen {
		*ptPtr = make([]byte, plaintextLen)
	}
	plaintext := (*ptPtr)[:plaintextLen]

	binary.BigEndian.PutUint16(plaintext[:2], uint16(len(b)))
	copy(plaintext[2:2+len(b)], b)
	if plaintextLen > 2+len(b) {
		if _, err := io.ReadFull(rand.Reader, plaintext[2+len(b):]); err != nil {
			return 0, err
		}
	}

	// 密钥衍生与 AEAD 流加密：
	kmPtr := keyMaterialPool.Get().(*[]byte)
	defer keyMaterialPool.Put(kmPtr)
	neededKM := len(c.password) + 8
	if cap(*kmPtr) < neededKM {
		*kmPtr = make([]byte, neededKM)
	}
	km := (*kmPtr)[:neededKM]
	copy(km, c.password)
	copy(km[len(c.password):], salt)
	key := blake2b.Sum256(km)

	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, salt)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return 0, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	wirePtr := wireBufPool.Get().(*[]byte)
	defer wireBufPool.Put(wirePtr)
	totalWire := 8 + len(ciphertext)
	if cap(*wirePtr) < totalWire {
		*wirePtr = make([]byte, totalWire)
	}
	wireBytes := (*wirePtr)[:totalWire]
	copy(wireBytes[:8], salt)
	copy(wireBytes[8:], ciphertext)

	if _, err := c.PacketConn.WriteTo(wireBytes, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}

func tryDecrypt(key, salt, ciphertext, b []byte) (int, bool) {
	if len(ciphertext) < 16+2 { // 必须包含 16 字节 Poly1305 Tag + 至少 2 字节原长
		return 0, false
	}
	kmPtr := keyMaterialPool.Get().(*[]byte)
	defer keyMaterialPool.Put(kmPtr)
	neededKM := len(key) + 8
	if cap(*kmPtr) < neededKM {
		*kmPtr = make([]byte, neededKM)
	}
	km := (*kmPtr)[:neededKM]
	copy(km, key)
	copy(km[len(key):], salt)
	derivedKey := blake2b.Sum256(km)

	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, salt)

	aead, err := chacha20poly1305.New(derivedKey[:])
	if err != nil {
		return 0, false
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, false // 密文被篡改或密钥错误，立即静默丢弃
	}

	if len(plaintext) < 2 {
		return 0, false
	}
	origLen := binary.BigEndian.Uint16(plaintext[:2])
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

	bufPtr := recvBufPool.Get().(*[]byte)
	defer recvBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}

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
