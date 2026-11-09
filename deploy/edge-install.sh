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
VERSION="1.2.38"

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

# 3. 输出就绪信息
echo "[3/3] AERO 安装完成！"
echo "使用说明:"
echo "  1. 运行 'aero cert' 签发/绑定权威公网证书 (支持 ACME 自动检测与实时生效)"
echo "  2. 运行 'aero' 进入交互式全功能管理菜单 (或运行 'systemctl start aero-edge' 启动服务)"
