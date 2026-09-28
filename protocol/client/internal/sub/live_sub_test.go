package sub

import (
	"testing"
)

func TestLiveFetchBothVPS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live VPS test in short mode")
	}
	urls := []string{
		"https://myconsun.de5.net/sub/d4248fda1bb4a5802dbd174b814571fd",
		"https://myconsun.cc.cd/sub/49adc46eff543149de857a49f89445b0",
	}

	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			doc, err := Fetch(u, FetchOptions{InsecureSkipVerify: false})
			if err != nil {
				t.Skipf("Live VPS subscription not reachable (%v), skipping live test", err)
				return
			}
			t.Logf("Fetched OK: version=%s, servers=%d", doc.Version, len(doc.Servers))
			for i, s := range doc.Servers {
				t.Logf("  Server[%d]: Name=%s, Addr=%s, SNI=%s, Protocol=%s, Pins=%v",
					i, s.Name, s.Address, s.SNI, s.Protocol, s.PinSPKI)
			}

			app, err := Apply(doc)
			if err != nil {
				t.Fatalf("Apply failed: %v", err)
			}
			t.Logf("  Applied: primary=%s, activeToken=%s, allPins=%v",
				app.EdgeAddresses, app.PrimaryToken, app.AllPins)
		})
	}
}
