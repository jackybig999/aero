// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package sub

import (
	"testing"
)

func TestNodeDomainPattern(t *testing.T) {
	for d, want := range map[string]bool{
		"node.example.com": true, "x7k2.edge.example.org": true,
		"": false, "203.0.113.5": false, "localhost": false, "a.b'; rm -rf /;'.com": false, "exa mple.com": false,
	} {
		if got := nodeDomainPattern.MatchString(d); got != want {
			t.Errorf("%q: %v", d, got)
		}
	}
}
