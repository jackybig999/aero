// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

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

// SalamanderPacketConn implements UDP obfuscation using Blake2b key derivation,
// ChaCha20-Poly1305 AEAD cipher, random salt, and dynamic padding jitter.
type SalamanderPacketConn struct {
	net.PacketConn
	password      []byte
	paddingJitter bool
}

// NewSalamanderPacketConn creates a new SalamanderPacketConn.
func NewSalamanderPacketConn(pconn net.PacketConn, password string, paddingJitter bool) *SalamanderPacketConn {
	return &SalamanderPacketConn{
		PacketConn:    pconn,
		password:      []byte(password),
		paddingJitter: paddingJitter,
	}
}

// WriteTo encrypts and obfuscates datagram b, sending it to addr.
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

		kmPtr := keyMaterialPool.Get().(*[]byte)
		neededKM := len(c.password) + 8
		if cap(*kmPtr) < neededKM {
			*kmPtr = make([]byte, neededKM)
		}
		km := (*kmPtr)[:neededKM]
		copy(km, c.password)
		copy(km[len(c.password):], salt)
		key := blake2b.Sum256(km)
		keyMaterialPool.Put(kmPtr)

		nonce := make([]byte, chacha20poly1305.NonceSize)
		copy(nonce, salt)

		aead, err := chacha20poly1305.New(key[:])
		if err != nil {
			continue
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue
		}

		if len(plaintext) < 2 {
			continue
		}
		origLen := binary.BigEndian.Uint16(plaintext[:2])
		if int(origLen) == 0 || int(origLen) > len(plaintext)-2 {
			continue
		}

		copyLen := int(origLen)
		if copyLen > len(b) {
			copyLen = len(b)
		}
		copy(b, plaintext[2:2+copyLen])
		return copyLen, addr, nil
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
