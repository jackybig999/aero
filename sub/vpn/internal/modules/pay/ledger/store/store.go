// Package store defines the data access interface for payment-ledger.
package store

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/domain"
)

var ErrNotFound = fmt.Errorf("entry not found")

// Store is the data access interface for the ledger.
// Only INSERT and mark-settled operations are allowed. No DELETE.
type Store interface {
	Append(e *domain.Entry) (uint64, error)
	GetByLedgerNo(no string) (*domain.Entry, error)
	ListAll() ([]domain.Entry, error)
	ListUnsettled(direction string) ([]domain.Entry, error)
	MarkSettled(ledgerNo, settlementNo string) error
	GetDailySummary(date time.Time) (*domain.Summary, error)
}

// MemoryStore is an in-memory implementation for testing.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]*domain.Entry
	nextID  atomic.Uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]*domain.Entry)}
}

func (m *MemoryStore) Append(e *domain.Entry) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[e.LedgerNo]; exists {
		return 0, fmt.Errorf("duplicate ledger_no: %s", e.LedgerNo)
	}
	id := m.nextID.Add(1)
	e.ID = id
	e.CreatedAt = time.Now()
	m.entries[e.LedgerNo] = e
	return id, nil
}

func (m *MemoryStore) GetByLedgerNo(no string) (*domain.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[no]
	if !ok {
		return nil, ErrNotFound
	}
	return e, nil
}

func (m *MemoryStore) ListAll() ([]domain.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []domain.Entry
	for _, e := range m.entries {
		result = append(result, *e)
	}
	return result, nil
}

func (m *MemoryStore) ListUnsettled(direction string) ([]domain.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []domain.Entry
	for _, e := range m.entries {
		if !e.Settled && e.Direction == direction {
			result = append(result, *e)
		}
	}
	return result, nil
}

// MarkSettled — the ONLY allowed mutation on ledger entries.
func (m *MemoryStore) MarkSettled(ledgerNo, settlementNo string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[ledgerNo]
	if !ok {
		return ErrNotFound
	}
	if e.Settled {
		return fmt.Errorf("already settled")
	}
	now := time.Now()
	e.Settled = true
	e.SettledAt = &now
	e.SettlementNo = settlementNo
	return nil
}

func (m *MemoryStore) GetDailySummary(date time.Time) (*domain.Summary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := &domain.Summary{Date: date.Format("2006-01-02")}
	for _, e := range m.entries {
		if e.CreatedAt.Format("2006-01-02") == s.Date {
			s.EntryCount++
			if e.Direction == "IN" {
				s.TotalInCents += e.AmountCents
			} else {
				s.TotalOutCents += e.AmountCents
			}
		}
	}
	return s, nil
}
