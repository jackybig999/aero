package edge

import (
	"fmt"
	"path/filepath"
)

// CleanupHost 是 `aero-edge cleanup-host` 的实现：在 edge 已停止（含崩溃）后还原宿主状态（ADR-0012）。
// 先取得数据目录的实例锁：edge 仍在运行时拒绝执行，避免删除运行中实例的规则。
// 供 systemd ExecStopPost 与运维手动调用；幂等。
func CleanupHost(dataDir string) error {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	lock, err := acquireInstanceLock(dir)
	if err != nil {
		return fmt.Errorf("edge appears to be running with data dir %s; stop it first: %w", dir, err)
	}
	restoreErr := RestoreHost(dir)
	if relErr := lock.release(); relErr != nil && restoreErr == nil {
		return relErr
	}
	return restoreErr
}
