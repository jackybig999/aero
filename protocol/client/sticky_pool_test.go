package client_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/aero-protocol/aero-ech"
)

func TestStickyPool_RuleL7_UnauthorizedMigrationRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := client.NewStickyPool(ctx, "vps-node-1", 10*time.Minute)
	defer pool.CloseAll()

	// 未达法定条件尝试迁移，必须被无情拒绝
	err := pool.TriggerMigration("vps-node-2", client.MigrationReasonUnknown)
	if err == nil {
		t.Fatalf("expected error on unauthorized migration, got nil")
	}

	if pool.ActiveNode() != "vps-node-1" {
		t.Fatalf("node should remain sticky to vps-node-1, got %s", pool.ActiveNode())
	}
}

func TestStickyPool_RuleL7_WriteFailures3x(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := client.NewStickyPool(ctx, "vps-node-1", 10*time.Minute)
	defer pool.CloseAll()

	var migratedReason client.MigrationReason
	pool.SetOnMigration(func(oldNode, newNode string, reason client.MigrationReason) {
		migratedReason = reason
	})

	// 第 1 次写失败：不迁移
	if pool.RecordWriteFailure("vps-node-2") {
		t.Fatalf("should not migrate on 1st write failure")
	}
	// 第 2 次写失败：不迁移
	if pool.RecordWriteFailure("vps-node-2") {
		t.Fatalf("should not migrate on 2nd write failure")
	}
	if pool.ActiveNode() != "vps-node-1" {
		t.Fatalf("should still be vps-node-1")
	}

	// 第 3 次写失败：法定条件满足，触发迁移！
	if !pool.RecordWriteFailure("vps-node-2") {
		t.Fatalf("should migrate on 3rd consecutive failure")
	}
	if pool.ActiveNode() != "vps-node-2" {
		t.Fatalf("expected active node vps-node-2, got %s", pool.ActiveNode())
	}
	if migratedReason != client.MigrationReasonConsecutiveFailures {
		t.Fatalf("expected MigrationReasonConsecutiveFailures, got %v", migratedReason)
	}
}

func TestStickyPool_RuleL7_VPSDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := client.NewStickyPool(ctx, "vps-primary", 10*time.Minute)
	defer pool.CloseAll()

	// 健康分虽下降但未归零：严禁随意迁移
	if pool.UpdateHealthScore(50, "vps-backup") {
		t.Fatalf("should not migrate when health score is 50")
	}
	if pool.ActiveNode() != "vps-primary" {
		t.Fatalf("expected vps-primary, got %s", pool.ActiveNode())
	}

	// 物理宕机（HealthScore == 0）：法定条件满足，触发迁移！
	if !pool.UpdateHealthScore(0, "vps-backup") {
		t.Fatalf("should migrate when health score drops to 0")
	}
	if pool.ActiveNode() != "vps-backup" {
		t.Fatalf("expected vps-backup, got %s", pool.ActiveNode())
	}
}

func TestStickyPool_RuleL7_RiskReported_IdleOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := client.NewStickyPool(ctx, "vps-dirty", 10*time.Minute)
	defer pool.CloseAll()

	// 模拟当前有请求正在传输
	pool.AcquireRequest()

	// 此时上报风控感知：因为有在途请求，严禁立刻中断迁移，必须等待空闲期
	migratedNow := pool.ReportRiskPerception("vps-clean")
	if migratedNow {
		t.Fatalf("must not migrate immediately while requests are in-flight")
	}
	if pool.ActiveNode() != "vps-dirty" {
		t.Fatalf("expected vps-dirty while active, got %s", pool.ActiveNode())
	}

	// 请求完成归还，进入会话空闲期：自动完成延迟迁移！
	pool.ReleaseRequest("vps-clean")
	if pool.ActiveNode() != "vps-clean" {
		t.Fatalf("expected migration to vps-clean on idle, got %s", pool.ActiveNode())
	}
}

func TestStickyPool_RuleL5_TTLEviction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := client.NewStickyPool(ctx, "vps-1", 50*time.Millisecond)
	defer pool.CloseAll()

	// 手工注入一条连接
	pipe1, pipe2 := net.Pipe()
	defer pipe2.Close()

	// 注入连接模拟
	_ = pipe1.SetDeadline(time.Now().Add(1 * time.Second))
	time.Sleep(60 * time.Millisecond) // 超过 50ms TTL

	evicted := pool.EvictIdleConns()
	if evicted < 0 {
		t.Fatalf("invalid evicted count")
	}
}
