// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import "testing"

func TestCongestionControlDefaultAndOverride(t *testing.T) {
	cases := []struct{ env, want string }{{"", "lossy"}, {"lossy", "lossy"}, {"cubic", "cubic"}, {"bbr", "lossy"}, {"CUBIC", "lossy"}}
	for _, c := range cases {
		t.Setenv(CongestionControlEnv, c.env)
		if got := congestionControl(); got != c.want {
			t.Errorf("env=%q: got %q, want %q", c.env, got, c.want)
		}
	}
}
