package service

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/store"
)

type Service struct{ s store.Store }

func New(s store.Store) *Service { return &Service{s: s} }

// CreateSubscription creates a subscription for a user on a node.
// uuid empty → auto-generate. One user may have many subs; one node serves many users.
func (svc *Service) CreateSubscription(userID, nodeID uint64, uuid string,
	nodeName, nodeIP string, nodePort int32, expireDate time.Time) (*domain.Subscription, error) {
	if userID == 0 || nodeID == 0 {
		return nil, fmt.Errorf("user_id and node_id required")
	}
	if expireDate.IsZero() || expireDate.Before(time.Now()) {
		return nil, fmt.Errorf("expire_date must be in the future")
	}
	if uuid == "" {
		uuid = newUUID()
	}
	if nodePort == 0 {
		nodePort = 443
	}
	sub := &domain.Subscription{
		UserID: userID, NodeID: nodeID, ClientUUID: uuid,
		Security: "auto", NodeName: nodeName, NodeIP: nodeIP, NodePort: nodePort,
		StartDate: time.Now(), ExpireDate: expireDate, Status: true,
	}
	if _, err := svc.s.Create(sub); err != nil {
		return nil, err
	}
	return sub, nil
}

// GetConfig returns client config by subscription UUID (AERO-oriented JSON for now).
func (svc *Service) GetConfig(uuid string) (map[string]any, error) {
	sub, err := svc.s.GetByUUID(uuid)
	if err != nil {
		return nil, fmt.Errorf("subscription not found: %w", err)
	}
	if sub.IsExpired() {
		return nil, fmt.Errorf("subscription expired")
	}
	// Dual shape: legacy v2ray fields + aero-friendly fields for client
	return map[string]any{
		"protocol":    "aero",
		"node_name":   sub.NodeName,
		"server":      sub.NodeIP,
		"port":        sub.NodePort,
		"client_uuid": sub.ClientUUID,
		"user_id":     sub.UserID,
		"node_id":     sub.NodeID,
		"expire_date": sub.ExpireDate,
	}, nil
}

func (svc *Service) ListAll() ([]domain.Subscription, error) { return svc.s.ListAll() }

func (svc *Service) ListByUser(userID uint64) ([]domain.Subscription, error) {
	all, err := svc.s.ListAll()
	if err != nil {
		return nil, err
	}
	var out []domain.Subscription
	for _, s := range all {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out, nil
}

// NodeSubCounts returns active (non-expired) subscription count per node_id.
func (svc *Service) NodeSubCounts() (map[uint64]int, error) {
	all, err := svc.s.ListAll()
	if err != nil {
		return nil, err
	}
	m := map[uint64]int{}
	now := time.Now()
	for _, s := range all {
		if s.Status && now.Before(s.ExpireDate) {
			m[s.NodeID]++
		}
	}
	return m, nil
}

func (svc *Service) DeleteSubscription(id uint64) error { return svc.s.Delete(id) }

// DetachNode deactivates then deletes all subscriptions for a removed node.
func (svc *Service) DetachNode(nodeID uint64) (deactivated, deleted int, err error) {
	if nodeID == 0 {
		return 0, 0, fmt.Errorf("node_id required")
	}
	deactivated, err = svc.s.DeactivateByNodeID(nodeID)
	if err != nil {
		return
	}
	deleted, err = svc.s.DeleteByNodeID(nodeID)
	return
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
