// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/quic-go/connect-ip-go"
)

// CopyTunnel 负责在 TUN 虚拟网卡与上层传输通道之间双向流转 IP 数据包
// 核心逻辑：双向无损流转，支持上下文取消与错误传播，自动关闭两端并回收资源
func CopyTunnel(ctx context.Context, tun io.ReadWriteCloser, ipConn io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = tun.Close()
			_ = ipConn.Close()
		})
	}

	// 1. tun -> ipConn
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := tun.Read(buf)
			if n > 0 {
				if _, werr := ipConn.Write(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// 2. ipConn -> tun
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := ipConn.Read(buf)
			if n > 0 {
				if _, werr := tun.Write(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// 3. 监听上下文取消
	go func() {
		<-ctx.Done()
		closeBoth()
	}()

	var retErr error
	select {
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-errCh:
		retErr = err
	}

	closeBoth()
	if errors.Is(retErr, io.EOF) || errors.Is(retErr, io.ErrClosedPipe) || errors.Is(retErr, net.ErrClosed) || errors.Is(retErr, context.Canceled) {
		return nil
	}
	return retErr
}

// CopyCONNECTIPTunnel bridges an OS TUN device (io.ReadWriteCloser) directly with an RFC 9484 CONNECT-IP tunnel.
func CopyCONNECTIPTunnel(ctx context.Context, tun io.ReadWriteCloser, ipConn *connectip.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = tun.Close()
			_ = ipConn.Close()
		})
	}

	// 1. tun -> connectip
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := tun.Read(buf)
			if n > 0 {
				if _, werr := ipConn.WritePacket(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// 2. connectip -> tun
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := ipConn.ReadPacket(buf)
			if n > 0 {
				if _, werr := tun.Write(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// 3. 监听上下文取消
	go func() {
		<-ctx.Done()
		closeBoth()
	}()

	var retErr error
	select {
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-errCh:
		retErr = err
	}

	closeBoth()
	if errors.Is(retErr, io.EOF) || errors.Is(retErr, io.ErrClosedPipe) || errors.Is(retErr, net.ErrClosed) || errors.Is(retErr, context.Canceled) {
		return nil
	}
	return retErr
}
