// Package domain defines core types for payment-ledger.
package domain

import "time"

// Entry represents a single immutable ledger record.
// Once written, amount/direction/channel fields NEVER change.
type Entry struct {
	ID           uint64     `json:"id"`
	LedgerNo     string     `json:"ledger_no"`
	UserID       uint64     `json:"user_id"`
	AmountCents  int64      `json:"amount_cents"` // always cents, never float
	Direction    string     `json:"direction"`    // "IN" or "OUT"
	Channel      string     `json:"channel"`
	ChannelRef   string     `json:"channel_ref,omitempty"`
	Settled      bool       `json:"settled"`
	SettledAt    *time.Time `json:"settled_at,omitempty"`
	SettlementNo string     `json:"settlement_no,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Summary represents a daily settlement summary.
type Summary struct {
	Date         string `json:"date"`
	TotalInCents int64  `json:"total_in_cents"`
	TotalOutCents int64 `json:"total_out_cents"`
	EntryCount   int    `json:"entry_count"`
}
