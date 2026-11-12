package sub

import (
	"path/filepath"
	"testing"
	"time"
)

// 删除节点记录只用非空条件：IP 为空时曾生成 address LIKE '%%'，删掉中台全部节点。
func TestDeleteNodeRowsIgnoresEmptyConditions(t *testing.T) {
	db, err := NewAeroDB(filepath.Join(t.TempDir(), "aero.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().Format(time.RFC3339)
	for _, r := range []struct {
		vps        int
		name, addr string
	}{{5, "n5", "198.51.100.5"}, {6, "n6", "198.51.100.6"}, {7, "n7", "203.0.113.7"}} {
		if _, err := db.db.Exec(`INSERT INTO node (vps_id, name, address, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, r.vps, r.name, r.addr, now, now); err != nil {
			t.Fatal(err)
		}
	}
	h := NewNodeHandler(NewNodeService())
	h.SetAeroDB(db)
	h.deleteNodeRows(0, 5, "", "") // 无 IP、无名称
	h.deleteNodeRows(0, 0, "", "") // 无任何条件：不删除
	var n int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM node`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("nodes left = %d (err %v), want 2", n, err)
	}
}
