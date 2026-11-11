#!/bin/bash
# AERO Edge — 完全对称卸载脚本 (Hyper-MASQUE 对称交付)
#
# 严格对称清理：
#   1) 停用并移除 systemd 守护进程
#   2) 原子销毁 nftables 表 (table inet aero_edge_default / aero_nat)
#   3) 按注释 Tag (aero_edge_default / AERO_V2_*) 精准清理 iptables 规则
#   4) 幂等销毁 aero-tun0 / aero-tun-* 虚拟网络接口
#   5) 还原原始 sysctl 内核参数备份并 reload，保障协议栈零污染残留
#   6) 彻底清理所有可执行产物、软链接、管理脚本与 CLI 终端工具
#   7) 清除 crontab 定时续签任务
#
set -euo pipefail

PURGE_DATA=0
INSTANCE_ID="default"

if [[ $EUID -ne 0 ]]; then
    echo "错误: 必须使用 root 用户执行卸载程序！"
    exit 1
fi

usage() {
    echo "AERO Edge 卸载程序"
    echo "用法: bash edge-uninstall.sh [INSTANCE_ID] [选项]"
    echo "  --purge, --all, -f  连同配置与数据目录 (/etc/aero, /var/lib/aero) 一并完全清除"
    echo "  -h, --help          显示帮助信息"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --purge|--all|-a|-f|--force) PURGE_DATA=1; shift ;;
        -h|--help) usage ;;
        -*) echo "未知选项: $1"; usage ;;
        *) INSTANCE_ID="$1"; shift ;;
    esac
done

echo "========================================="
echo " 开始对称卸载 AERO Edge 节点服务 (实例: ${INSTANCE_ID})"
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

# 1b. 还原宿主（删除带 aero_edge_default 标记的转发规则、还原 ip_forward，ADR-0012），须在删除程序前执行
if [[ -x /usr/local/bin/aero-edge ]]; then
    /usr/local/bin/aero-edge cleanup-host || echo "[warn] cleanup-host failed; run it manually before removing the binary"
fi

# 2. 清理 nftables 规则
if command -v nft >/dev/null 2>&1; then
    for table_name in "aero_edge_${INSTANCE_ID}" "aero_edge_default" "aero_nat"; do
        if nft list tables inet 2>/dev/null | grep -qw "$table_name"; then
            echo "[nftables] 原子销毁 table inet ${table_name}..."
            nft delete table inet "$table_name" 2>/dev/null || true
        fi
    done
fi

# 3. 按 Tag 精准清理 iptables 规则 (§7.1 & G3)
TAG="AERO_V2_${INSTANCE_ID}"
if command -v iptables >/dev/null 2>&1; then
    echo "[iptables] 按 Tag (aero_edge_default / ${TAG}) 精准清理防火墙与 NAT 规则..."
    
    # 清理 NAT 表中标记有 aero_edge_default 或 TAG 的规则
    while read -r rule; do
        if [[ -n "$rule" ]] && [[ "$rule" =~ aero_edge_default || "$rule" =~ ${TAG} ]]; then
            del_rule="${rule/-A/-D}"
            iptables -t nat $del_rule 2>/dev/null || true
        fi
    done < <(iptables -t nat -S 2>/dev/null | grep -E "(aero_edge_default|${TAG})" || true)

    # 清理 Filter 表中标记有 aero_edge_default 或 TAG 的规则
    while read -r rule; do
        if [[ -n "$rule" ]] && [[ "$rule" =~ aero_edge_default || "$rule" =~ ${TAG} ]]; then
            del_rule="${rule/-A/-D}"
            iptables $del_rule 2>/dev/null || true
        fi
    done < <(iptables -S 2>/dev/null | grep -E "(aero_edge_default|${TAG})" || true)
fi

# 4. 幂等销毁 aero-tun 接口
for tun_dev in "aero-tun-${INSTANCE_ID}" "aero-tun0"; do
    if ip link show "$tun_dev" >/dev/null 2>&1; then
        echo "[network] 销毁 ${tun_dev} 虚拟网络接口..."
        ip link set "$tun_dev" down 2>/dev/null || true
        if ip tuntap list 2>/dev/null | grep -qw "$tun_dev"; then
            ip tuntap del dev "$tun_dev" mode tun 2>/dev/null || true
        else
            ip link delete "$tun_dev" 2>/dev/null || true
        fi
    fi
done

# 5. 还原 sysctl 内核网络参数 (落地方案 §7.1 & 门禁 G3)
echo "[sysctl] 恢复网络协议栈初始配置..."
for conf in "/etc/aero/${INSTANCE_ID}/sysctl_orig.conf" "/etc/aero/sysctl_orig.conf"; do
    if [[ -f "$conf" ]]; then
        sysctl -p "$conf" >/dev/null 2>&1 || true
        rm -f "$conf"
        echo "[sysctl] 已严格从 $conf 恢复宿主机内核原始参数"
    fi
done
if [[ -d "/etc/aero/${INSTANCE_ID}" && -z "$(ls -A "/etc/aero/${INSTANCE_ID}" 2>/dev/null)" ]]; then
    rmdir "/etc/aero/${INSTANCE_ID}" 2>/dev/null || true
fi

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

# 6. 清理可执行产物、软链接、管理脚本与全局 CLI 工具 (杜绝陈旧脚本残留)
echo "[bin] 清理可执行产物与全局管理工具..."
for b in "/usr/local/bin/aeroprot-edge" "/usr/local/bin/aero-edge" "/usr/local/bin/aero-edge.bak" \
         "/usr/local/bin/aero" "/usr/bin/aero" \
         "/usr/local/bin/edge-uninstall.sh" "/usr/local/bin/edge-install.sh"; do
    if [[ -f "$b" || -L "$b" ]]; then
        rm -f "$b"
        echo "[bin] 已彻底清理: $b"
    fi
done

# 7. 清理由 AERO 注册的 crontab 续签定时任务
if crontab -l 2>/dev/null | grep -q "aero-edge"; then
    echo "[cron] 清理 crontab 定时任务..."
    (crontab -l 2>/dev/null | grep -v "aero-edge" || true) | crontab - 2>/dev/null || true
fi

# 8. 可选数据清理
if [[ "$PURGE_DATA" -eq 1 ]]; then
    echo "[data] 完全清除配置与运行时数据目录 (/etc/aero, /var/lib/aero)..."
    rm -rf /etc/aero /var/lib/aero
fi

echo "========================================="
echo " AERO Edge 对称卸载完成，宿主机环境与协议栈已彻底还原"
echo "========================================="
