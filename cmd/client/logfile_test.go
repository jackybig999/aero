// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRedactLogLine(t *testing.T) {
	cases := map[string]string{
		`initial subscription loaded from https://mid.example.com/sub/SECRET-TOKEN-123`:         `initial subscription loaded from https://mid.example.com/…`,
		`Get "https://mid.example.com:8443/api/v1/sub?token=abc&x=1": dial tcp: timeout`:        `Get "https://mid.example.com:8443/…": dial tcp: timeout`,
		`[GEODATA] updated: 110000 rules from https://n1.example.com:443/api/v1/geodata/direct`: `[GEODATA] updated: 110000 rules from https://n1.example.com:443/…`,
		`a http://x.example/p and https://y.example/q/r?z=1 done`:                               `a http://x.example/… and https://y.example/… done`,
		`no url here, just text 1.2.3.4:443`:                                                    `no url here, just text 1.2.3.4:443`,
		`bare host https://mid.example.com stays`:                                               `bare host https://mid.example.com stays`,
	}
	for in, want := range cases {
		if got := string(redactLogLine([]byte(in))); got != want {
			t.Errorf("脱敏结果不对\n in:   %s\n got:  %s\n want: %s", in, got, want)
		}
		if strings.Contains(string(redactLogLine([]byte(in))), "SECRET-TOKEN") {
			t.Errorf("令牌未被打码: %s", in)
		}
	}
}

func TestSetupLogFileWritesRedactedAndRotates(t *testing.T) {
	dir := t.TempDir()
	origOut, origFlags := log.Writer(), log.Flags()
	defer func() { log.SetOutput(origOut); log.SetFlags(origFlags) }()

	closeFn, err := setupLogFile(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	log.SetFlags(0)
	log.Printf("loaded from %s", "https://mid.example.com/sub/TOPSECRET")
	closeFn()

	b, err := os.ReadFile(filepath.Join(dir, logFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "TOPSECRET") || !strings.Contains(string(b), "https://mid.example.com/…") {
		t.Fatalf("日志内容不对: %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(dir, logFileName)); fi.Mode().Perm() != 0o600 {
			t.Errorf("日志权限 = %v, 期望 0600", fi.Mode().Perm())
		}
	}

	// 超过阈值：旧日志改名为 .1，新日志重新开始
	if err := os.WriteFile(filepath.Join(dir, logFileName), make([]byte, logRotateBytes+10), 0o600); err != nil {
		t.Fatal(err)
	}
	closeFn, err = setupLogFile(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("after rotate")
	closeFn()
	if fi, err := os.Stat(filepath.Join(dir, logFileName+".1")); err != nil || fi.Size() <= logRotateBytes {
		t.Errorf("应保留轮转后的旧日志: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, logFileName)); !strings.Contains(string(b), "after rotate") || len(b) > 200 {
		t.Errorf("轮转后应是新文件: %d 字节", len(b))
	}
}

func TestSetupLogFileFailureKeepsLogging(t *testing.T) {
	// 数据目录不可用（路径被文件占用）：返回错误，不 panic，标准日志仍可用
	f := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := setupLogFile(filepath.Join(f, "sub"), false); err == nil {
		t.Error("目录不可用应返回错误")
	}
}
