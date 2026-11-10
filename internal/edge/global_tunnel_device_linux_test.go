//go:build linux

package edge

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEdgeTunIfreqUsesKernelSizedStruct(t *testing.T) {
	ifr, err := newEdgeTunIfreq("aero-tun0")
	if err != nil {
		t.Fatalf("newEdgeTunIfreq: %v", err)
	}
	if got := ifr.Name(); got != "aero-tun0" {
		t.Fatalf("Name() = %q, want aero-tun0", got)
	}
	if got := ifr.Uint16(); got != unix.IFF_TUN|unix.IFF_NO_PI {
		t.Fatalf("flags = %#x, want IFF_TUN|IFF_NO_PI (%#x)", got, unix.IFF_TUN|unix.IFF_NO_PI)
	}
}

func TestEdgeTunIfreqRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", strings.Repeat("x", unix.IFNAMSIZ)} {
		if _, err := newEdgeTunIfreq(name); err == nil {
			t.Errorf("newEdgeTunIfreq(%q) succeeded, want error", name)
		}
	}
}
