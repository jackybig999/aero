package domain

import "time"

type Subscription struct {
	ID         uint64    `json:"id"`
	UserID     uint64    `json:"user_id"`
	NodeID     uint64    `json:"node_id"`
	ClientUUID string    `json:"client_uuid"`
	Security   string    `json:"security"`
	StartDate  time.Time `json:"start_date"`
	ExpireDate time.Time `json:"expire_date"`
	Status     bool      `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	// Joined from nodes
	NodeName string `json:"node_name,omitempty"`
	NodeIP   string `json:"node_ip,omitempty"`
	NodePort int32  `json:"node_port,omitempty"`
}

func (s *Subscription) IsExpired() bool { return time.Now().After(s.ExpireDate) }

// V2RayConfig mirrors V2Ray client expectations.
// Field names from vps old code Subscription.config action.
type V2RayConfig struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port int32  `json:"port"`
	ID   string `json:"id"`
	AID  int32  `json:"aid"`
	SCY  string `json:"scy"`
	Net  string `json:"net"`  // vps old code default: "tcp"
	Type string `json:"type"` // vps old code default: "none"
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
}
