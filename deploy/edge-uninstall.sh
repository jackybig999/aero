#!/bin/bash
# AERO Edge — 完全对称卸载脚本 (Hyper-MASQUE 对称交付)
#
# 严格对称清理：
#   1) 停用并移除 systemd 守护进程
#   2) 原子销毁 nftables 表 (table inet aero_edge_default)
#   3) 按注释 Tag (aero_edge_default) 精准清理 iptables 规则
#   4) 幂等销毁 aero-tun0 虚拟网络接口
#   5) 还原原始 sysctl 内核参数备份并 reload，保障协议栈零污染残留
#
set -euo pipefail

PURGE_DATA=0

usage() {
    echo "AERO Edge 卸载程序"
    echo "用法: bash edge-uninstall.sh [选项]"
    echo "  --purge        连同配置与数据目录 (/etc/aero, /var/lib/aero) 一并完全清除"
    echo "  -h, --help     显示帮助信息"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --purge) PURGE_DATA=1; shift ;;
        -h|--help) usage ;;
        *) echo "未知选项: $1"; usage ;;
    esac
done

echo "========================================="
echo " 开始对称卸载 AERO Edge 节点服务"
echo "========================================="

# 1. 停止并禁用 systemd 服务
if systemctl is-active --quiet aero-edge 2>/dev/null; then
    echo "[systemd] 停止 aero-edge 运行..."
    systemctl stop aero-edge || true
fi

if systemctl is-enabled --quiet aero-edge 2>/dev/null; then
    echo "[systemd] 禁用 aero-edge 自启动..."
    systemctl disable aero-edge || true
fi

if [[ -f "/etc/systemd/system/aero-edge.service" ]]; then
    rm -f "/etc/systemd/system/aero-edge.service"
    systemctl daemon-reload || true
    echo "[systemd] 已移除 aero-edge.service"
fi

# 2. 清理 nftables 规则
if command -v nft >/dev/null 2>&1; then
    if nft list tables inet 2>/dev/null | grep -qw "aero_edge_default"; then
        echo "[nftables] 原子销毁 table inet aero_edge_default..."
        nft delete table inet aero_edge_default 2>/dev/null || true
    fi
fi

# 3. 按 Tag 精准清理 iptables 规则
if command -v iptables >/dev/null 2>&1; then
    echo "[iptables] 按 Tag (aero_edge_default) 精准清理防火墙与 NAT 规则..."
    
    # 清理 NAT 表中标记有 aero_edge_default 的规则
    while read -r rule; do
        if [[ -n "$rule" && "$rule" =~ aero_edge_default ]]; then
            del_rule="${rule/-A/-D}"
            iptables -t nat $del_rule 2>/dev/null || true
        fi
    done < <(iptables -t nat -S 2>/dev/null | grep "aero_edge_default" || true)

    # 清理 Filter 表中标记有 aero_edge_default 的规则
    while read -r rule; do
        if [[ -n "$rule" && "$rule" =~ aero_edge_default ]]; then
            del_rule="${rule/-A/-D}"
            iptables $del_rule 2>/dev/null || true
        fi
    done < <(iptables -S 2>/dev/null | grep "aero_edge_default" || true)
fi

# 4. 幂等销毁 aero-tun0 接口
if ip link show aero-tun0 >/dev/null 2>&1; then
    echo "[network] 销毁 aero-tun0 虚拟网络接口..."
    ip link set aero-tun0 down 2>/dev/null || true
    ip link delete aero-tun0 2>/dev/null || true
fi

# 5. 还原 sysctl 内核网络参数
echo "[sysctl] 恢复网络协议栈初始配置..."
if [[ -f "/etc/sysctl.d/99-aero-sysctl.conf.bak" ]]; then
    mv -f "/etc/sysctl.d/99-aero-sysctl.conf.bak" "/etc/sysctl.d/99-aero-sysctl.conf"
    echo "[sysctl] 已恢复 99-aero-sysctl.conf 备份文件"
else
    rm -f "/etc/sysctl.d/99-aero-sysctl.conf"
fi

if [[ -f "/etc/sysctl.d/99-aero-bbr.conf.bak" ]]; then
    mv -f "/etc/sysctl.d/99-aero-bbr.conf.bak" "/etc/sysctl.d/99-aero-bbr.conf"
    echo "[sysctl] 已恢复 99-aero-bbr.conf 备份文件"
else
    rm -f "/etc/sysctl.d/99-aero-bbr.conf"
fi

sysctl --system >/dev/null 2>&1 || true

# 6. 清理可执行二进制
if [[ -f "/usr/local/bin/aero-edge" ]]; then
    rm -f "/usr/local/bin/aero-edge"
fi
if [[ -f "/usr/local/bin/aero-edge.bak" ]]; then
    rm -f "/usr/local/bin/aero-edge.bak"
fi

# 7. 可选数据清理
if [[ "$PURGE_DATA" -eq 1 ]]; then
    echo "[data] 完全清除 /etc/aero 与 /var/lib/aero..."
    rm -rf /etc/aero /var/lib/aero
fi

echo "========================================="
echo " AERO Edge 对称卸载完成，协议栈已还原"
echo "========================================="
