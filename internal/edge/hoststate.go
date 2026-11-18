package edge

import (
	"fmt"
	"os"
	"path/filepath"
)

// CleanupHost 是 `aero-edge cleanup-host` 的实现：在 edge 已停止（含崩溃）后还原宿主状态（ADR-0012）。
// 先取得数据目录的实例锁：edge 仍在运行时拒绝执行，避免删除运行中实例的规则。
// 数据目录不存在（从未运行过或已卸载）时没有实例可锁、也没有日志，视为无需还原 ip_forward，但仍回收
// 可能残留的带标记规则与 nft 自有表（RestoreHost 在没有日志时只做按标记的清理，不修改其他状态）。
// 供 systemd ExecStopPost 与运维手动调用；幂等。
func CleanupHost(dataDir string) error {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	if _, serr := os.Stat(dir); os.IsNotExist(serr) {
		return RestoreHost(dir)
	} else if serr != nil {
		return fmt.Errorf("stat data dir %s: %w", dir, serr)
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
