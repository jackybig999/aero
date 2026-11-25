// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// roundTripFunc 让测试用函数充当 HTTP 传输层。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// 服务器关闭（ctx 取消）之后，后台 geo 刷新协程不得再往数据目录落盘：此前它只在取消时中止了网络请求，
// 但已经在飞行中、取消后才完成的那一次仍会走到 MkdirAll + 写 .tmp + rename，把已被删除的数据目录重新创建出来
// （CI 里表现为 TempDir 清理时 "directory not empty" 的偶发失败，如 TestConnectUDP/LongRangeEcho）。
func TestGeoDataCronDoesNotPersistAfterCancel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	h := NewGeoDataHandler(dir)

	release := make(chan struct{})
	started := make(chan struct{}, 4)
	h.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-release // 模拟取消之后才完成的响应（忽略 ctx）
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("late.example\n")), Header: http.Header{}}, nil
	})}

	ctx, cancel := context.WithCancel(context.Background())
	h.StartCronUpdate(ctx)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("后台刷新没有开始请求")
	}
	cancel() // 服务器关闭
	close(release)

	done := make(chan struct{})
	go func() { h.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait 没有在后台协程退出后返回")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(dir)
		t.Fatalf("取消之后后台协程仍然往数据目录落盘了: err=%v entries=%v", err, entries)
	}
}

// Wait 会等后台协程：协程还在飞行中时 Wait 不返回，放行后才返回。
func TestGeoDataWaitBlocksUntilBackgroundExits(t *testing.T) {
	h := NewGeoDataHandler(t.TempDir())
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	h.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return nil, context.Canceled
	})}
	ctx, cancel := context.WithCancel(context.Background())
	h.StartCronUpdate(ctx)
	<-started
	done := make(chan struct{})
	go func() { h.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("协程还在飞行中，Wait 不应返回")
	case <-time.After(150 * time.Millisecond):
	}
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("取消后 Wait 应返回")
	}
}
