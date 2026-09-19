package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/domain"
)

type FileStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]*domain.Entry
	nextID  uint64
}

type ledgerSnapshot struct {
	NextID  uint64                   `json:"next_id"`
	Entries map[string]*domain.Entry `json:"entries"`
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		path = filepath.Join("data", "ledger.json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("ledger dir: %w", err)
	}
	fs := &FileStore{
		path:    path,
		entries: make(map[string]*domain.Entry),
	}
	_ = fs.load()
	return fs, nil
}

func (f *FileStore) load() error {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snap ledgerSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Entries != nil {
		f.entries = snap.Entries
	}
	f.nextID = snap.NextID
	return nil
}

func (f *FileStore) persistLocked() error {
	snap := ledgerSnapshot{
		NextID:  f.nextID,
		Entries: f.entries,
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *FileStore) Append(e *domain.Entry) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.entries[e.LedgerNo]; exists {
		return 0, fmt.Errorf("duplicate ledger_no: %s", e.LedgerNo)
	}
	f.nextID++
	e.ID = f.nextID
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	f.entries[e.LedgerNo] = e
	_ = f.persistLocked()
	return e.ID, nil
}

func (f *FileStore) GetByLedgerNo(no string) (*domain.Entry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.entries[no]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *e
	return &cp, nil
}

func (f *FileStore) ListAll() ([]domain.Entry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var result []domain.Entry
	for _, e := range f.entries {
		result = append(result, *e)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func (f *FileStore) ListUnsettled(direction string) ([]domain.Entry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var result []domain.Entry
	for _, e := range f.entries {
		if !e.Settled && (direction == "" || e.Direction == direction) {
			result = append(result, *e)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func (f *FileStore) MarkSettled(ledgerNo, settlementNo string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[ledgerNo]
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
	return f.persistLocked()
}

func (f *FileStore) GetDailySummary(date time.Time) (*domain.Summary, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	target := date.Format("2006-01-02")
	s := &domain.Summary{Date: target}
	for _, e := range f.entries {
		if e.CreatedAt.Format("2006-01-02") == target {
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
