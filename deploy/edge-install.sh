#!/usr/bin/env bash
# ==============================================================================
# AERO Edge — 轻量级极简安装引导器 (Zero Server Coupling)
# 职责边界：纯粹的二进制下载与 systemd 服务托管，绝不侵入任何网络/防火墙/证书逻辑
# ==============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "错误: 必须使用 root 用户执行安装程序！"
    exit 1
fi

DOMAIN=""
ADMIN_KEY=""
TOKEN=""
PORT="443"
LOCAL_BIN=""
REPO="jackybig999/aero"
VERSION="1.2.35"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -k|--admin-key) ADMIN_KEY="$2"; shift 2 ;;
        -t|--token) TOKEN="$2"; shift 2 ;;
        -p|--port) PORT="$2"; shift 2 ;;
        -b|--binary) LOCAL_BIN="$2"; shift 2 ;;
        -h|--help)
            echo "用法: bash edge-install.sh -d <域名> [选项]"
            echo "选项:"
            echo "  -d, --domain DOMAIN     公网绑定域名 (必须)"
            echo "  -k, --admin-key KEY     管理员 API / Web 控制台密钥"
            echo "  -t, --token TOKEN       初始客户端连接 Token (可选，默认自动生成)"
            echo "  -p, --port PORT         主监听端口 (默认 443)"
            echo "  -b, --binary PATH       使用本地预编译二进制文件安装"
            exit 0
            ;;
        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$1"
            elif [[ -z "$ADMIN_KEY" ]]; then
                ADMIN_KEY="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    read -r -p "请输入节点绑定的公网合法域名 (如 edge.example.com): " DOMAIN
fi
if [[ -z "$DOMAIN" ]]; then
    echo "错误: 必须提供公网域名！"
    exit 1
fi

ARCH="amd64"
[ "$(uname -m)" = "aarch64" ] && ARCH="arm64"

mkdir -p /usr/local/bin /etc/aero /var/lib/aero

# 1. 部署二进制产物
echo "[1/4] 安装 AERO Edge 核心服务..."
if [[ -n "$LOCAL_BIN" && -f "$LOCAL_BIN" ]]; then
    cp -f "$LOCAL_BIN" /usr/local/bin/aero-edge
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/edge_linux_${ARCH}"
    echo "正在从 GitHub Release 下载最新二进制: ${DOWNLOAD_URL}"
    curl -fsSL "$DOWNLOAD_URL" -o /usr/local/bin/aero-edge || {
        echo "从 latest 下载失败，尝试从当前版本 v${VERSION} 下载..."
        curl -fsSL "https://github.com/${REPO}/releases/download/v${VERSION}/edge_linux_${ARCH}" -o /usr/local/bin/aero-edge
    }
fi
chmod +x /usr/local/bin/aero-edge

# 部署命令行管理工具
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [[ -f "${SCRIPT_DIR}/aero" ]]; then
    cp -f "${SCRIPT_DIR}/aero" /usr/local/bin/aero
    chmod +x /usr/local/bin/aero
elif [[ -f "/usr/local/bin/aero-edge" ]]; then
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/deploy/aero" -o /usr/local/bin/aero 2>/dev/null || true
    chmod +x /usr/local/bin/aero 2>/dev/null || true
fi

# 2. 写入标准化启动配置 (所有网络、防火墙、ACME、BBR 由服务端 Go 二进制内部自驱)
PRIMARY_PORT="${PORT}"
echo "[2/4] 写入服务基础配置..."
cat > /etc/aero/edge.json <<EOF
{
  "listen": ":${PRIMARY_PORT}",
  "domain": "${DOMAIN}",
  "admin_key": "${ADMIN_KEY}",
  "token": "${TOKEN}",
  "data_dir": "/var/lib/aero"
}
EOF

cat > /etc/aero/edge.conf <<EOF
AERO_DOMAIN="${DOMAIN}"
AERO_PORTS="${PRIMARY_PORT}"
AERO_ADMIN_KEY="${ADMIN_KEY}"
EOF
chmod 600 /etc/aero/edge.json /etc/aero/edge.conf

# 防火墙与网络：由服务端 Go 二进制内部自驱治理 (nat_linux.go 动态挂载并保证进程退出时完全对称清理)

# 3. 注册并启动 systemd 系统服务
echo "[3/4] 注册并启动 systemd 守护进程..."
cat > /etc/systemd/system/aero-edge.service <<EOF
[Unit]
Description=AERO Edge High-Performance Protocol Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aero-edge -config /etc/aero/edge.json -listen :${PRIMARY_PORT}
Restart=always
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now aero-edge

# 4. 输出就绪信息
echo "[4/4] AERO Edge 服务安装已完成并启动！"
sleep 1
if [[ -x "/usr/local/bin/aero" ]]; then
    /usr/local/bin/aero info || true
fi
