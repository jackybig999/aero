// Copyright 2026 AERO Protocol Contributors
// Plan.md Phase 2: 平铺测试 — 纯 Go SQLite 双轨记账与并发事务测试
package mid

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSQLiteStoreOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_ledger.db")

	s, err := NewSQLiteLedgerStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteLedgerStore failed: %v", err)
	}
	defer s.Close()

	// 1. 测试写入条目 (Append)
	e1 := &LedgerEntry{
		LedgerNo:    "TX_1001",
		UserID:      101,
		AmountCents: 5000,
		Direction:   "IN",
		Channel:     "stripe",
		ChannelRef:  "ch_test_123",
		CreatedAt:   time.Now(),
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

	// 4. 追加更多条目测试列表
	e2 := &LedgerEntry{
		LedgerNo:    "TX_1002",
		UserID:      102,
		AmountCents: 2000,
		Direction:   "OUT",
		Channel:     "alipay",
		CreatedAt:   time.Now(),
	}
	_, err = s.Append(e2)
	if err != nil {
		t.Fatalf("Append e2 failed: %v", err)
	}

	all, total, err := s.List(0, 10)
	if err != nil || total != 2 || len(all) != 2 {
		t.Fatalf("expected 2 entries, got len=%d, total=%d (err: %v)", len(all), total, err)
	}
}

func TestSQLiteStoreConcurrentAppend(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "concurrent_ledger.db")

	s, err := NewSQLiteLedgerStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteLedgerStore failed: %v", err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	workers := 10
	entriesPerWorker := 15

	for i := 0; i < workers; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < entriesPerWorker; j++ {
				e := &LedgerEntry{
					LedgerNo:    filepath.Join(string(rune('A'+workerID)), string(rune('0'+j))),
					UserID:      uint64(workerID*100 + j),
					AmountCents: int64((workerID + 1) * 10),
					Direction:   "IN",
					Channel:     "test",
					CreatedAt:   time.Now(),
				}
				if _, err := s.Append(e); err != nil {
					t.Errorf("concurrent append failed: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	all, total, err := s.List(0, workers*entriesPerWorker+10)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if total != int64(workers*entriesPerWorker) || len(all) != workers*entriesPerWorker {
		t.Fatalf("expected %d entries, got %d (len: %d)", workers*entriesPerWorker, total, len(all))
	}
}
