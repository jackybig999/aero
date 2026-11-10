//go:build linux && !android

package client

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestClientTunIfreqUsesKernelSizedStruct(t *testing.T) {
	ifr, err := newClientTunIfreq("aero0")
	if err != nil {
		t.Fatalf("newClientTunIfreq: %v", err)
	}
	if got := ifr.Name(); got != "aero0" {
		t.Fatalf("Name() = %q, want aero0", got)
	}
	if got := ifr.Uint16(); got != unix.IFF_TUN|unix.IFF_NO_PI {
		t.Fatalf("flags = %#x, want IFF_TUN|IFF_NO_PI (%#x)", got, unix.IFF_TUN|unix.IFF_NO_PI)
	}
}

func TestClientTunIfreqRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", strings.Repeat("x", unix.IFNAMSIZ)} {
		if _, err := newClientTunIfreq(name); err == nil {
			t.Errorf("newClientTunIfreq(%q) succeeded, want error", name)
		}
	}
}
