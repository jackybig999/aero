// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime/debug"
	"sync"

	"github.com/quic-go/connect-ip-go"
)

// mobileBufPool provides a zero-heap-allocation 1500-byte buffer pool for mobile TUN processing.
var mobileBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1500)
		return &b
	},
}

// InitMobileRuntime optimizes Go runtime memory and GC parameters for constrained mobile environments
// balancing iOS Network Extension Jetsam budget and high-throughput GC efficiency.
func InitMobileRuntime() {
	debug.SetMemoryLimit(20 * 1024 * 1024)
	debug.SetGCPercent(50)
}

// MobileTunnelController manages the lifecycle of a mobile TUN tunnel.
type MobileTunnelController struct {
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	err      error
	stopOnce sync.Once
}

// Stop gracefully stops the mobile tunnel and releases both endpoints.
func (c *MobileTunnelController) Stop() error {
	c.stopOnce.Do(func() {
		c.cancel()
	})
	<-c.done
	return c.err
}

// Done returns the channel that is closed when the tunnel completes teardown.
func (c *MobileTunnelController) Done() <-chan struct{} {
	return c.done
}

// Err returns the exit error of the tunnel, if any.
func (c *MobileTunnelController) Err() error {
	return c.err
}

// StartMobileTunnel starts a mobile TUN tunnel with lifecycle control.
// When ctx is canceled or Stop() is called, both tun and ipConn are closed
// and all background goroutines are cleanly reaped within 100ms.
func StartMobileTunnel(ctx context.Context, tun io.ReadWriteCloser, ipConn io.ReadWriteCloser) *MobileTunnelController {
	if ctx == nil {
		ctx = context.Background()
	}
	cCtx, cancel := context.WithCancel(ctx)
	ctrl := &MobileTunnelController{
		ctx:    cCtx,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go func() {
		defer close(ctrl.done)
		ctrl.err = CopyTunnel(cCtx, tun, ipConn)
	}()

	return ctrl
}

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

	var wg sync.WaitGroup
	wg.Add(2)

	// 1. tun -> ipConn
	go func() {
		defer wg.Done()
		bufPtr := mobileBufPool.Get().(*[]byte)
		defer mobileBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, err := tun.Read(buf)
			if n > 0 {
				if _, werr := ipConn.Write(buf[:n]); werr != nil {
					select {
					case errCh <- werr:
					default:
					}
					return
				}
			}
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
		}
	}()

	// 2. ipConn -> tun
	go func() {
		defer wg.Done()
		bufPtr := mobileBufPool.Get().(*[]byte)
		defer mobileBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, err := ipConn.Read(buf)
			if n > 0 {
				if _, werr := tun.Write(buf[:n]); werr != nil {
					select {
					case errCh <- werr:
					default:
					}
					return
				}
			}
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
		}
	}()

	// 3. 监听上下文取消
	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-ctxDone:
		}
	}()

	var retErr error
	select {
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-errCh:
		retErr = err
	}

	closeBoth()
	close(ctxDone)
	wg.Wait()

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

	var wg sync.WaitGroup
	wg.Add(2)

	// 1. tun -> connectip
	go func() {
		defer wg.Done()
		bufPtr := mobileBufPool.Get().(*[]byte)
		defer mobileBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, err := tun.Read(buf)
			if n > 0 {
				if _, werr := ipConn.WritePacket(buf[:n]); werr != nil {
					select {
					case errCh <- werr:
					default:
					}
					return
				}
			}
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
		}
	}()

	// 2. connectip -> tun
	go func() {
		defer wg.Done()
		bufPtr := mobileBufPool.Get().(*[]byte)
		defer mobileBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, err := ipConn.ReadPacket(buf)
			if n > 0 {
				if _, werr := tun.Write(buf[:n]); werr != nil {
					select {
					case errCh <- werr:
					default:
					}
					return
				}
			}
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
		}
	}()

	// 3. 监听上下文取消
	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-ctxDone:
		}
	}()

	var retErr error
	select {
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-errCh:
		retErr = err
	}

	closeBoth()
	close(ctxDone)
	wg.Wait()

	if errors.Is(retErr, io.EOF) || errors.Is(retErr, io.ErrClosedPipe) || errors.Is(retErr, net.ErrClosed) || errors.Is(retErr, context.Canceled) {
		return nil
	}
	return retErr
}
