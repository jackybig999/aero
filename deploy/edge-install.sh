#!/usr/bin/env bash
# ==============================================================================
# AERO Edge — 纯净系统安装引导器 (Pure Delivery Installer)
# 职责边界：纯粹的二进制产物部署与最简 Linux 标准 systemd 托管
# 严禁：任何用户交互询问、任何参数解析、任何配置文件生成
# ==============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "错误: 必须使用 root 用户执行安装程序！"
    exit 1
fi

ARCH="amd64"
[ "$(uname -m)" = "aarch64" ] && ARCH="arm64"

mkdir -p /usr/local/bin /etc/aero /var/lib/aero

# 1. 部署二进制产物
REPO="jackybig999/aero"
VERSION="1.2.39"

echo "[1/3] 下载并安装 AERO Edge 核心程序..."
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/edge_linux_${ARCH}"
curl -fsSL "$DOWNLOAD_URL" -o /usr/local/bin/aero-edge 2>/dev/null || {
    curl -fsSL "https://github.com/${REPO}/releases/download/v${VERSION}/edge_linux_${ARCH}" -o /usr/local/bin/aero-edge
}
chmod +x /usr/local/bin/aero-edge

# 部署命令行管理工具
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [[ -f "${SCRIPT_DIR}/aero" ]]; then
    cp -f "${SCRIPT_DIR}/aero" /usr/local/bin/aero
    chmod +x /usr/local/bin/aero
else
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/deploy/aero" -o /usr/local/bin/aero 2>/dev/null || true
    chmod +x /usr/local/bin/aero 2>/dev/null || true
fi

# 2. 注册 Linux 最简标准 systemd 托管服务
echo "[2/3] 注册 systemd 系统守护进程..."
cat > /etc/systemd/system/aero-edge.service <<EOF
[Unit]
Description=AERO Edge Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/aero-edge
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now aero-edge 2>/dev/null || true

# 3. 等待服务端完成自主初始化与避让自愈
echo "[3/3] 等待 AERO 服务端完成初始化与配置写盘..."
sleep 1.5

# 从服务端已写盘的配置中读取真实生效状态
DOMAIN=""
PRIMARY_PORT="443"
ADMIN_KEY=""
if [[ -f "/etc/aero/edge.json" ]]; then
    DOMAIN=$(grep -o '"domain":[^,]*' /etc/aero/edge.json 2>/dev/null | cut -d'"' -f4 || true)
    ADMIN_KEY=$(grep -o '"admin_key":[^,]*' /etc/aero/edge.json 2>/dev/null | cut -d'"' -f4 || true)
    P_STR=$(grep -o '"listen":[^,]*' /etc/aero/edge.json 2>/dev/null | cut -d'"' -f4 || true)
    if [[ -n "$P_STR" ]]; then
        PRIMARY_PORT="${P_STR#:}"
    fi
fi

PORT_SUFFIX=""
if [[ -n "$PRIMARY_PORT" && "$PRIMARY_PORT" != "443" ]]; then
    PORT_SUFFIX=":${PRIMARY_PORT}"
fi
DISPLAY_DOMAIN="${DOMAIN:-$(curl -s4 icanhazip.com 2>/dev/null || echo "127.0.0.1")}"

# 控制台管理密钥确认与自定义引导 (支持 curl 管道交互)
echo ""
echo "===================================================="
echo "          配置 AERO Edge Web 控制台访问密钥         "
echo "===================================================="
echo " 当前服务端生成密钥: ${ADMIN_KEY:-已生成}"
echo " 密钥格式规范提示:   建议 8-32 位字符 (如: MySecret@2026 或 admin123)"
echo " 用于直接访问控制台: https://${DISPLAY_DOMAIN}${PORT_SUFFIX}/console?key=<您的密钥>"
echo "----------------------------------------------------"

USER_KEY=""
if [ -t 0 ] || [ -e /dev/tty ]; then
    read -r -p "请输入自定义管理密钥 Key [直接回车使用上述生成的安全密钥]: " USER_KEY </dev/tty || USER_KEY=""
fi

if [[ -n "$USER_KEY" ]]; then
    ADMIN_KEY="$USER_KEY"
    if [[ -f "/etc/aero/edge.json" ]]; then
        if grep -q '"admin_key"' /etc/aero/edge.json; then
            sed -i 's/"admin_key": *"[^"]*"/"admin_key": "'"${ADMIN_KEY}"'"/' /etc/aero/edge.json
        else
            sed -i 's/{/{\n  "admin_key": "'"${ADMIN_KEY}"'",/' /etc/aero/edge.json
        fi
    fi
    systemctl restart aero-edge 2>/dev/null || true
fi

echo ""
echo "===================================================="
echo "               AERO Edge 部署就绪                   "
echo "===================================================="
echo " 节点域名:       ${DISPLAY_DOMAIN}"
echo " 监听主端口:     :${PRIMARY_PORT}"
echo " 管理密钥:       ${ADMIN_KEY}"
echo "----------------------------------------------------"
echo " Web 控制台直达: https://${DISPLAY_DOMAIN}${PORT_SUFFIX}/console?key=${ADMIN_KEY}"
echo " 管理员全量订阅: https://${DISPLAY_DOMAIN}${PORT_SUFFIX}/sub/admin"
echo "===================================================="
echo "使用说明:"
echo "  1. 复制上方 Web 控制台直达链接即可直接打开管理页面；"
echo "  2. 随时在终端输入 'aero' 可进入循环菜单，或运行 'aero key' / 'aero port' 修改密钥与端口。"
