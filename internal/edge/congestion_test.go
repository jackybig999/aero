// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCongestionControl(t *testing.T) {
	t.Setenv(CongestionControlEnv, "")
	cases := []struct{ env, cfg, want string }{
		{"", "", "cubic"}, // 服务端默认（灰度，节点用 aero cc lossy 开启）
		{"", "lossy", "lossy"},
		{"", "cubic", "cubic"},
		{"", "bogus", "cubic"},      // 无效配置回落到默认
		{"cubic", "lossy", "cubic"}, // 环境变量优先
		{"lossy", "cubic", "lossy"},
		{"bogus", "lossy", "lossy"}, // 无效环境变量被忽略
	}
	for _, c := range cases {
		t.Setenv(CongestionControlEnv, c.env)
		if got := ResolveCongestionControl(c.cfg); got != c.want {
			t.Errorf("env=%q cfg=%q: got %q, want %q", c.env, c.cfg, got, c.want)
		}
	}
}

func TestConfigSetCongestionControl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.json")
	for _, v := range []string{"lossy", "cubic"} {
		if _, err := ConfigSet(path, "congestion_control", v); err != nil {
			t.Fatalf("set %q: %v", v, err)
		}
		if got, err := ConfigGet(path, "congestion_control"); err != nil || got != v {
			t.Fatalf("get after set %q: %q %v", v, got, err)
		}
	}
	for _, bad := range []string{"", "bbr", "CUBIC ", "true"} {
		if _, err := ConfigSet(path, "congestion_control", bad); err == nil {
			t.Errorf("set %q 应被拒绝", bad)
		}
	}
	if got, _ := ConfigGet(path, "congestion_control"); got != "cubic" {
		t.Errorf("非法输入不应改动已有值: %q", got)
	}
}

func TestCheckNodeReportsCongestionControl(t *testing.T) {
	t.Setenv(CongestionControlEnv, "")
	dir := t.TempDir()
	for _, tc := range []struct{ cfg, level, detail string }{
		{`{"congestion_control":"lossy"}`, "OK", "lossy"},
		{`{}`, "OK", "cubic"},
		{`{"congestion_control":"bbr"}`, "FAIL", "invalid"},
	} {
		p := filepath.Join(dir, "edge.json")
		if err := os.WriteFile(p, []byte(tc.cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		var found *CheckItem
		for _, it := range CheckNode(p) {
			if it.Name == "congestion_control" {
				it := it
				found = &it
			}
		}
		if found == nil || found.Level != tc.level || !strings.Contains(found.Detail, tc.detail) {
			t.Errorf("cfg=%s: got %+v, want %s containing %q", tc.cfg, found, tc.level, tc.detail)
		}
	}
}

// 入口到出口的多跳拨号与监听侧用同一个拥塞控制设置（ADR-0019）。
func TestHopCongestionControlFollowsConfig(t *testing.T) {
	t.Setenv(CongestionControlEnv, "")
	var nilServer *QUICServer
	if got := nilServer.hopCongestionControl(); got != DefaultCongestionControl {
		t.Errorf("nil server: %q", got)
	}
	for cfgValue, want := range map[string]string{"": "cubic", "lossy": "lossy", "cubic": "cubic", "bogus": "cubic"} {
		s := &QUICServer{cfg: &ServerConfig{CongestionControl: cfgValue}}
		if got := s.hopCongestionControl(); got != want {
			t.Errorf("cfg=%q: got %q, want %q", cfgValue, got, want)
		}
	}
	t.Setenv(CongestionControlEnv, "lossy")
	if got := (&QUICServer{cfg: &ServerConfig{CongestionControl: "cubic"}}).hopCongestionControl(); got != "lossy" {
		t.Errorf("环境变量应优先: %q", got)
	}
}

// aero cc 用 config get 显示当前取值：未设置或无效时给出默认值，而不是空串。
func TestConfigGetCongestionControlDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.json")
	if got, err := ConfigGet(path, "congestion_control"); err != nil || got != DefaultCongestionControl {
		t.Fatalf("未设置: %q %v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"congestion_control":"bogus"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := ConfigGet(path, "congestion_control"); got != DefaultCongestionControl {
		t.Errorf("无效值应显示默认: %q", got)
	}
	if _, err := ConfigSet(path, "congestion_control", "lossy"); err != nil {
		t.Fatal(err)
	}
	if got, _ := ConfigGet(path, "congestion_control"); got != "lossy" {
		t.Errorf("设置后: %q", got)
	}
}
