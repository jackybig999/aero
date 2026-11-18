#!/usr/bin/env bash
# AERO Edge 卸载：只删除 AERO 自己安装的内容（服务单元、程序、运维命令），并还原 edge 对宿主的修改。
# --purge 时同时删除 /etc/aero 与 /var/lib/aero。不卸载 acme.sh、WARP 等独立软件（由 `aero uninstall` 逐项询问）。
set -euo pipefail

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1
[[ $EUID -eq 0 ]] || { echo "需要 root 权限" >&2; exit 1; }

systemctl disable --now aero-edge 2>/dev/null || true
# 服务单元的 ExecStopPost 已还原宿主；再执行一次以覆盖服务早已停止的情况（幂等）
if [[ -x /usr/local/bin/aero-edge ]]; then
  if ! /usr/local/bin/aero-edge cleanup-host -config /etc/aero/edge.json; then
    # 全新安装（从未运行过）可能因目录不存在而失败：只读确认确无残留才视为无需清理
    residue=0
    [[ -e /var/lib/aero/host-state.json ]] && residue=1
    if command -v nft >/dev/null && nft list table inet aero_edge >/dev/null 2>&1; then residue=1; fi
    rules=$( (iptables-save; ip6tables-save) 2>/dev/null || true )
    if grep -q aero_edge_default <<<"$rules"; then residue=1; fi
    if [[ $residue -eq 1 ]]; then
      echo "错误: cleanup-host 失败，宿主上仍有 AERO 的转发规则或状态；已停止卸载（未删除程序与数据）。" >&2
      echo "下一步: 修复后重新运行卸载；或检查 iptables -S / nft list table inet aero_edge" >&2
      exit 1
    fi
    echo "提示: cleanup-host 失败，但未发现需要还原的宿主改动，继续卸载。" >&2
  fi
fi
rm -f /etc/systemd/system/aero-edge.service
rm -rf /etc/systemd/system/aero-edge.service.d
systemctl daemon-reload
systemctl reset-failed aero-edge 2>/dev/null || true
rm -f /usr/local/bin/aero-edge /usr/local/bin/aero
rm -rf /usr/local/lib/aero
if [[ $PURGE -eq 1 ]]; then
  rm -rf /etc/aero /var/lib/aero
  echo "已卸载 AERO Edge，并删除配置与数据。"
else
  echo "已卸载 AERO Edge（保留 /etc/aero 与 /var/lib/aero）。"
fi
