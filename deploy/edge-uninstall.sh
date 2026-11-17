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
  /usr/local/bin/aero-edge cleanup-host -config /etc/aero/edge.json || echo "警告: cleanup-host 失败" >&2
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
