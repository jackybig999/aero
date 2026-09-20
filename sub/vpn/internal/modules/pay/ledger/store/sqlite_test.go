package store

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/domain"
)

func TestSQLiteStoreOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_ledger.db")

	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer s.Close()

	// 1. 测试写入条目 (Append)
	e1 := &domain.Entry{
		LedgerNo:    "TX_1001",
		UserID:      101,
		AmountCents: 5000,
		Direction:   "IN",
		Channel:     "stripe",
		ChannelRef:  "ch_test_123",
	}
	id1, err := s.Append(e1)
	if err != nil {
		t.Fatalf("Append e1 failed: %v", err)
	}
	if id1 != 1 {
		t.Errorf("expected id 1, got %d", id1)
	}

	// 2. 测试重复凭单号排重 (Duplicate LedgerNo)
	_, err = s.Append(e1)
	if err == nil {
		t.Fatalf("expected error on duplicate ledger_no, got nil")
	}

	// 3. 测试查询单个条目 (GetByLedgerNo)
	got, err := s.GetByLedgerNo("TX_1001")
	if err != nil {
		t.Fatalf("GetByLedgerNo failed: %v", err)
	}
	if got.AmountCents != 5000 || got.Channel != "stripe" || got.Settled {
		t.Errorf("unexpected entry data: %+v", got)
	}

	// 4. 追加更多条目测试列表与未清算查询
	e2 := &domain.Entry{
		LedgerNo:    "TX_1002",
		UserID:      102,
		AmountCents: 2000,
		Direction:   "OUT",
		Channel:     "alipay",
	}
	_, err = s.Append(e2)
	if err != nil {
		t.Fatalf("Append e2 failed: %v", err)
	}

	all, err := s.ListAll()
	if err != nil || len(all) != 2 {
		t.Fatalf("expected 2 entries, got %d (err: %v)", len(all), err)
	}

	unsettledIn, err := s.ListUnsettled("IN")
	if err != nil || len(unsettledIn) != 1 {
		t.Fatalf("expected 1 unsettled IN entry, got %d (err: %v)", len(unsettledIn), err)
	}

	// 5. 测试清算标记 (MarkSettled)
	if err := s.MarkSettled("TX_1001", "SETTLE_20260920"); err != nil {
		t.Fatalf("MarkSettled failed: %v", err)
	}
	gotSettled, err := s.GetByLedgerNo("TX_1001")
	if err != nil {
		t.Fatalf("GetByLedgerNo after settled failed: %v", err)
	}
	if !gotSettled.Settled || gotSettled.SettlementNo != "SETTLE_20260920" || gotSettled.SettledAt == nil {
		t.Errorf("expected settled entry, got: %+v", gotSettled)
	}

	unsettledAfter, err := s.ListUnsettled("IN")
	if err != nil || len(unsettledAfter) != 0 {
		t.Fatalf("expected 0 unsettled IN entries after settlement, got %d", len(unsettledAfter))
	}

	// 6. 测试每日统计汇总 (GetDailySummary)
	summary, err := s.GetDailySummary(time.Now())
	if err != nil {
		t.Fatalf("GetDailySummary failed: %v", err)
	}
	if summary.TotalInCents != 5000 || summary.TotalOutCents != 2000 || summary.EntryCount != 2 {
		t.Errorf("unexpected summary: %+v", summary)
	}
}

func TestSQLiteStoreConcurrentAppend(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "concurrent_ledger.db")

	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	workers := 10
	entriesPerWorker := 20

	for i := 0; i < workers; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < entriesPerWorker; j++ {
				e := &domain.Entry{
					LedgerNo:    filepath.Join(string(rune('A'+workerID)), string(rune('0'+j))),
					UserID:      uint64(workerID*100 + j),
					AmountCents: int64((workerID + 1) * 10),
					Direction:   "IN",
					Channel:     "test",
				}
				if _, err := s.Append(e); err != nil {
					t.Errorf("concurrent append failed: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	all, err := s.ListAll()
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}
	if len(all) != workers*entriesPerWorker {
		t.Fatalf("expected %d entries, got %d", workers*entriesPerWorker, len(all))
	}
}
