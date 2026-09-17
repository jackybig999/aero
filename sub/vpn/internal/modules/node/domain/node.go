package domain

import "time"

type Node struct {
	ID            uint64     `json:"id"`
	VPSID         uint64     `json:"vps_id"`
	Name          string     `json:"name"`
	Region        string     `json:"region"`
	IP            string     `json:"ip"`
	Port          int32      `json:"port"`
	Protocol      string     `json:"protocol"`
	Status        bool       `json:"status"`
	MaxUsers      int32      `json:"max_users"`
	CurrentUsers  int32      `json:"current_users"`
	IsBackup      bool       `json:"is_backup"`
	Weight        int32      `json:"weight"`
	AgentVersion  string     `json:"agent_version,omitempty"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (n *Node) LoadPercent() float64 {
	if n.MaxUsers > 0 {
		return float64(n.CurrentUsers) / float64(n.MaxUsers) * 100
	}
	return 0
}
