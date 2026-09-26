// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package aero

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// WriteMessage 写入 4 字节大端长度 + Protobuf 消息。
// 默认在握手前 4 包中注入随机高熵 Padding，打破固定报文长度分布特征。
func WriteMessage(w io.Writer, msg proto.Message) error {
	return WriteMessageWithPadding(w, msg, nil)
}

// WriteMessageWithPadding 遵循铁律 L4（无锁前 4 包混淆断流）：
// 单协程持有 padCount 指针：
// - 当 padCount == nil 或 *padCount < 4 时：注入 64~256 字节高熵 Padding，单次栈数组系统调用，零堆分配；
// - 当 *padCount >= 4 时：坚决切断 Padding，0 次 rand.Read 系统调用，达到线速线载吞吐。
func WriteMessageWithPadding(w io.Writer, msg proto.Message, padCount *uint8) error {
	bp := getBuffer()
	defer putBuffer(bp)

	// 预置 4 字节长度占位符
	*bp = append(*bp, 0, 0, 0, 0)

	var err error
	*bp, err = proto.MarshalOptions{}.MarshalAppend(*bp, msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// 判定是否注入混淆 Padding
	shouldPad := (padCount == nil) || (*padCount < 4)
	if shouldPad {
		// 单次系统调用读取高熵随机数（栈数组 257 字节，0 堆逃逸）
		var entropyBuf [257]byte
		_, _ = rand.Read(entropyBuf[:])
		padLen := 64 + int(entropyBuf[0])%193 // 范围 [64, 256] 动态变长
		padBytes := entropyBuf[1 : 1+padLen]

		// 使用标准 Protobuf Length-Delimited (Tag 15) 注入 Padding
		*bp = protowire.AppendTag(*bp, 15, protowire.BytesType)
		*bp = protowire.AppendBytes(*bp, padBytes)

		if padCount != nil {
			*padCount++
		}
	}

	// 填写真实总载荷长度（包含 Padding）
	payloadLen := len(*bp) - 4
	binary.BigEndian.PutUint32((*bp)[:4], uint32(payloadLen))

	if _, err := w.Write(*bp); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	return nil
}
