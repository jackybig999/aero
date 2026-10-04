// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

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

		keyMaterial := make([]byte, len(c.password)+8)
		copy(keyMaterial, c.password)
		copy(keyMaterial[len(c.password):], salt)
		key := blake2b.Sum256(keyMaterial)

		nonce := make([]byte, chacha20poly1305.NonceSize)
		copy(nonce, salt)

		aead, err := chacha20poly1305.New(key[:])
		if err != nil {
			continue
		}

		// Open 执行 ChaCha20 解密并严格校验 Poly1305 MAC 认证标签
		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue // 密文被篡改或密码错误，静默丢弃
		}

		if len(plaintext) < 2 {
			continue
		}
		origLen := binary.BigEndian.Uint16(plaintext[:2])
		// 若 int(origLen) > len(plaintext)-2，数据损坏/长度不合法，静默丢弃
		if int(origLen) == 0 || int(origLen) > len(plaintext)-2 {
			continue
		}

		// 复制 plaintext[2 : 2+origLen] 到 b，返回 int(origLen), addr, nil！
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
