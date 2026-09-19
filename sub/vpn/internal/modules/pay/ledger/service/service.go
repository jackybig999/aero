// Package service implements payment-ledger business logic.
// ALL amount fields are in cents (int64). Floats are NEVER used.
package service

import (
	"fmt"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/pay/ledger/store"
)

type Service struct {
	store store.Store
}

func New(s store.Store) *Service { return &Service{store: s} }

// RecordPayment inserts a new immutable ledger entry.
// amountCents must be positive. direction must be IN or OUT.
func (s *Service) RecordPayment(userID uint64, amountCents int64, direction, channel, channelRef string) (*domain.Entry, error) {
	if amountCents <= 0 {
		return nil, fmt.Errorf("amount must be positive")
	}
	if direction != "IN" && direction != "OUT" {
		return nil, fmt.Errorf("direction must be IN or OUT")
	}
	now := time.Now()
	e := &domain.Entry{
		LedgerNo:    fmt.Sprintf("LED-%s-%s", now.Format("20060102"), nextSeq()),
		UserID:      userID,
		AmountCents: amountCents,
		Direction:   direction,
		Channel:     channel,
		ChannelRef:  channelRef,
	}
	if _, err := s.store.Append(e); err != nil {
		return nil, err
	}
	return e, nil
}

func (s *Service) GetByLedgerNo(no string) (*domain.Entry, error) { return s.store.GetByLedgerNo(no) }

func (s *Service) ListAll() ([]domain.Entry, error) {
	return s.store.ListAll()
}

func (s *Service) ListUnsettled(direction string) ([]domain.Entry, error) {
	if direction == "" { direction = "IN" }
	return s.store.ListUnsettled(direction)
}

// MarkSettled is the ONLY allowed modification on ledger entries.
func (s *Service) MarkSettled(ledgerNo, settlementNo string) error {
	return s.store.MarkSettled(ledgerNo, settlementNo)
}

// SettleBatch 资金归集结算：汇总未结算 IN 流水，生成汇总 OUT 记录，并将原单标记为已结算
func (s *Service) SettleBatch(channel, targetRef string) (*domain.Entry, int, error) {
	unsettled, err := s.store.ListUnsettled("IN")
	if err != nil {
		return nil, 0, err
	}
	if len(unsettled) == 0 {
		return nil, 0, fmt.Errorf("无待结算入账记录")
	}
	var totalCents int64
	for _, it := range unsettled {
		totalCents += it.AmountCents
	}
	now := time.Now()
	setNo := fmt.Sprintf("SET-%s-%04x", now.Format("20060102"), now.UnixNano()%0xffff)
	for _, it := range unsettled {
		_ = s.store.MarkSettled(it.LedgerNo, setNo)
	}
	if channel == "" {
		channel = "PingPong"
	}
	if targetRef == "" {
		targetRef = "归集账户: " + setNo
	}
	outEntry, err := s.RecordPayment(0, totalCents, "OUT", channel, targetRef)
	if err != nil {
		return nil, len(unsettled), err
	}
	_ = s.store.MarkSettled(outEntry.LedgerNo, setNo)
	return outEntry, len(unsettled), nil
}

func (s *Service) GetDailySummary(date time.Time) (*domain.Summary, error) {
	return s.store.GetDailySummary(date)
}

// seq is a simple non-crypto sequence for ledger_no uniqueness.
var seq struct{ n int64 }

func nextSeq() string {
	seq.n++
	return fmt.Sprintf("%08x", seq.n)
}
