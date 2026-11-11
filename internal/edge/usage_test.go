package edge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func usageToken(uid string) string {
	p, _ := json.Marshal(map[string]any{"v": 1, "iss": "sub", "uid": uid})
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

func newTestMeter(t *testing.T, now *time.Time) (*UsageMeter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "usage.db")
	m, err := OpenUsageMeter(path)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return *now }
	t.Cleanup(func() { _ = m.Close() })
	return m, path
}

func TestUsageCellOnlyForSignedTokens(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 30, 0, 0, time.UTC)
	m, _ := newTestMeter(t, &now)
	if m.Cell("tok_opaque") != nil || m.Cell("aero1.!!!.x") != nil {
		t.Fatal("opaque or malformed tokens must not be metered")
	}
	a, b := m.Cell(usageToken("user_alice01")), m.Cell(usageToken("user_alice01"))
	if a == nil || a != b {
		t.Fatal("same uid must share one cell")
	}
	var nilCell *usageCell
	nilCell.Add(10, 10) // 不计量的会话：无操作、不崩溃
}

func TestUsageFlushPageAndCursor(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 30, 0, 0, time.UTC)
	m, _ := newTestMeter(t, &now)
	alice, bob := m.Cell(usageToken("user_alice01")), m.Cell(usageToken("user_bob00001"))
	alice.Add(100, 1000)
	bob.Add(5, 50)
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	recs, cur, err := m.Page("", 10)
	if err != nil || len(recs) != 2 {
		t.Fatalf("page = %+v, %v", recs, err)
	}
	alice.Add(1, 10) // 同一小时再次变化：同一行累计，seq 变大
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	recs2, cur2, err := m.Page(cur, 10)
	if err != nil || len(recs2) != 1 || recs2[0].UID != "user_alice01" || recs2[0].BytesUp != 101 || recs2[0].BytesDown != 1010 ||
		recs2[0].Seq <= recs[1].Seq || recs2[0].PeriodStart != now.Truncate(time.Hour).Unix() || recs2[0].Final {
		t.Fatalf("after second flush: %+v (cursor %s)", recs2, cur2)
	}
	if again, cur3, _ := m.Page(cur2, 10); len(again) != 0 || cur3 != cur2 {
		t.Fatalf("no new data must return the same cursor: %+v %s", again, cur3)
	}
	// 跨小时：新行；上一小时标记 final
	now = now.Add(time.Hour)
	bob.Add(1, 1)
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	all, _, _ := m.Page("", 10)
	var finals, open int
	for _, r := range all {
		if r.Final {
			finals++
		} else {
			open++
		}
	}
	if len(all) != 3 || finals != 2 || open != 1 {
		t.Fatalf("hour rollover: %+v", all)
	}
	if _, _, err := m.Page("abc", 10); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}

func TestUsagePruneExpiresOldCursorsAndKeepsSeqMonotonic(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 30, 0, 0, time.UTC)
	m, _ := newTestMeter(t, &now)
	c, d := m.Cell(usageToken("user_carol01")), m.Cell(usageToken("user_dan00001"))
	c.Add(1, 1)
	_ = m.Flush()
	d.Add(1, 1)
	_ = m.Flush()
	old, oldCur, _ := m.Page("", 10)
	if len(old) != 2 || oldCur != "2" {
		t.Fatalf("setup: %+v %s", old, oldCur)
	}
	// 只清理旧小时；新小时的行保留
	now = now.Add(100 * 24 * time.Hour)
	if err := m.store.prune(now.Add(-usageRetention).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Page("1", 10); !errors.Is(err, ErrUsageCursorExpired) {
		t.Fatalf("cursor inside the pruned range: err = %v, want ErrUsageCursorExpired", err)
	}
	if _, _, err := m.Page(oldCur, 10); err != nil {
		t.Fatalf("cursor at the pruned boundary lost nothing and must work: %v", err)
	}
	if _, _, err := m.Page("", 10); err != nil {
		t.Fatalf("reading from the start must work after prune: %v", err)
	}
	// 清理后 MAX(seq) 回退为 0，新 seq 仍必须大于被清理的
	c.Add(3, 3)
	_ = m.Flush()
	recs, _, _ := m.Page("", 10)
	if len(recs) != 1 || recs[0].Seq <= 2 {
		t.Fatalf("seq reused after prune: %+v", recs)
	}
}

func TestUsageConcurrentAddAndPersistence(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	m, path := newTestMeter(t, &now)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cell := m.Cell(usageToken("user_dave0001"))
			for i := 0; i < 1000; i++ {
				cell.Add(1, 2)
				if i%250 == 0 {
					_ = m.Flush()
				}
			}
		}()
	}
	wg.Wait()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m2, err := OpenUsageMeter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	m2.now = func() time.Time { return now }
	recs, _, err := m2.Page("", 10)
	if err != nil || len(recs) != 1 || recs[0].BytesUp != 8000 || recs[0].BytesDown != 16000 {
		t.Fatalf("after concurrent adds and reopen: %+v %v", recs, err)
	}
}
