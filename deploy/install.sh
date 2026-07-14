#!/bin/bash
# AERO Edge — 一键安装（A 阶段：数据目录与 /sub 同源）
#
# 用法:
#   bash install.sh -d edge.example.com              # 域名 + ACME
#   bash install.sh -i 1.2.3.4 -p 443                # 无域名 IP + 自签 + pin
#   bash install.sh -d edge.example.com -b ./aero-edge  # 指定本地二进制
#
set -euo pipefail

TOKEN=""
DOMAIN=""
ADVERTISE_IP=""
EMAIL=""
PORTS="443"
SNI=""
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/aero"
DATA_DIR="/var/lib/aero"
CERT_DIR="/var/lib/aero/certs"
LOG_DIR="/var/log"
VERSION="2.0.0"
REPO="aero-protocol/aero-protocol"
LOCAL_BIN=""

usage() {
    echo "AERO Edge 一键安装"
    echo "  -d, --domain DOMAIN     域名（ACME；与 -i 二选一或同时：域名优先证书）"
    echo "  -i, --ip IP             无域名时写入订阅的公网 IP"
    echo "  -t, --token TOKEN       可选，默认自动生成"
    echo "  -e, --email EMAIL       Let's Encrypt 邮箱"
    echo "  -p, --ports PORTS       默认 443（勿依赖未完成的 QUIC 端口）"
    echo "  -s, --sni SNI           TLS SNI / 证书名"
    echo "  -b, --binary PATH       本地 aero-edge 二进制（优先于下载）"
    echo "  -h, --help"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--token) TOKEN="$2"; shift 2 ;;
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -i|--ip) ADVERTISE_IP="$2"; shift 2 ;;
        -e|--email) EMAIL="$2"; shift 2 ;;
        -p|--ports) PORTS="$2"; shift 2 ;;
        -s|--sni) SNI="$2"; shift 2 ;;
        -b|--binary) LOCAL_BIN="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "未知选项: $1"; usage ;;
    esac
done

if [[ -z "$DOMAIN" && -z "$ADVERTISE_IP" ]]; then
    echo "错误: 请提供 -d DOMAIN 或 -i IP"
    usage
fi
if [[ -z "$TOKEN" ]]; then
    TOKEN="aero_$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    echo "提示: 已自动生成 token"
fi
if [[ -z "$SNI" ]]; then
    if [[ -n "$DOMAIN" ]]; then SNI="$DOMAIN"; else SNI="$ADVERTISE_IP"; fi
fi
if [[ -z "$EMAIL" && -n "$DOMAIN" ]]; then
    EMAIL="admin@${DOMAIN}"
fi

ADVERTISE_HOST="${DOMAIN:-$ADVERTISE_IP}"
PRIMARY_PORT=$(echo "$PORTS" | cut -d, -f1 | tr -d ' ')

echo "========================================="
echo " AERO Edge v${VERSION}"
echo " advertise: $ADVERTISE_HOST"
echo " ports:     $PORTS"
echo " data:      $DATA_DIR"
echo "========================================="

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="armv7" ;;
esac

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$CERT_DIR"

# --- 配置 ---
if [[ -n "$DOMAIN" ]]; then
TLS_YAML="  tls:
    mode: autocert
    autocert:
      domain: \"$DOMAIN\"
      email: \"$EMAIL\"
      cache_dir: \"$CERT_DIR\""
else
TLS_YAML="  tls:
    mode: selfsigned"
fi

cat > "$CONFIG_DIR/server.yaml" << YAML
aero:
  version: "1.0"
server:
  listen:
    ports: [$(echo "$PORTS" | tr ',' ' ')]
$TLS_YAML
  ech:
    public_name: "$SNI"
  auth:
    tokens:
      - token: "$TOKEN"
        user: "default"
        ttl: 8760h
  log:
    file: "$LOG_DIR/aero-edge.log"
    format: json
YAML

cat > "$CONFIG_DIR/edge.conf" << CONF
AERO_DATA_DIR=$DATA_DIR
AERO_TOKEN=$TOKEN
AERO_DOMAIN=$DOMAIN
AERO_PORTS=$PORTS
AERO_SNI=$SNI
CONF

# --- 二进制 ---
echo "[bin] install aero-edge -> $INSTALL_DIR/aero-edge"
if [[ -n "$LOCAL_BIN" && -f "$LOCAL_BIN" ]]; then
    cp -f "$LOCAL_BIN" "$INSTALL_DIR/aero-edge"
    chmod +x "$INSTALL_DIR/aero-edge"
    echo "[bin] used local: $LOCAL_BIN"
else
    BINARY_URL="https://github.com/${REPO}/releases/download/v${VERSION}/aero-edge-linux-${ARCH}"
    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/aero-edge"; then
            echo "[bin] 下载失败: $BINARY_URL"
            echo "[bin] 请: go build -o aero-edge ./aero-edge/cmd/aero-edge && bash install.sh -b ./aero-edge ..."
            exit 1
        fi
    else
        echo "需要 curl 或 -b 本地二进制"; exit 1
    fi
    chmod +x "$INSTALL_DIR/aero-edge"
fi

# --- systemd：固定 WorkingDirectory + AERO_DATA_DIR ---
cat > /etc/systemd/system/aero-edge.service << SERVICE
[Unit]
Description=AERO Edge Server
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=$DATA_DIR
Environment=AERO_DATA_DIR=$DATA_DIR
EnvironmentFile=$CONFIG_DIR/edge.conf
ExecStart=$INSTALL_DIR/aero-edge \\
  -config $CONFIG_DIR/server.yaml \\
  -data-dir $DATA_DIR \\
  -advertise-host $ADVERTISE_HOST \\
  -sni $SNI \\
  -token $TOKEN \\
  -ports $PORTS
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable aero-edge
systemctl restart aero-edge

echo "[wait] edge writing subscription..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -f "$DATA_DIR/sub_meta.json" && -f "$DATA_DIR/client-sub.json" ]]; then
        break
    fi
    sleep 1
done

if [[ ! -f "$DATA_DIR/sub_meta.json" ]]; then
    echo "错误: 未生成 $DATA_DIR/sub_meta.json"
    journalctl -u aero-edge -n 40 --no-pager || true
    exit 1
fi

SUB_SECRET=$(python3 -c "import json;print(json.load(open('$DATA_DIR/sub_meta.json'))['secret'])" 2>/dev/null || true)
# 安装侧再写一份到 CONFIG（与 DATA 内容一致，方便备份）
cp -f "$DATA_DIR/client-sub.json" "$CONFIG_DIR/client-sub.json"

SUB_URL="https://${ADVERTISE_HOST}:${PRIMARY_PORT}/sub/${SUB_SECRET}"
if [[ -z "$SUB_SECRET" ]]; then
    SUB_URL="(见 $DATA_DIR/sub_meta.json)"
fi

echo ""
echo "========================================="
echo " 安装完成 — 客户端一键导入"
echo "========================================="
echo " Token:      $TOKEN"
echo " Data dir:   $DATA_DIR"
echo " Sub file:   $DATA_DIR/client-sub.json"
echo " Sub URL:    $SUB_URL"
echo ""
echo " 命令:"
echo "   aero-ech -sub $DATA_DIR/client-sub.json"
echo "   # 或（公网可达时）"
echo "   aero-ech -sub $SUB_URL"
echo ""
if command -v qrencode >/dev/null 2>&1 && [[ -n "$SUB_SECRET" ]]; then
    echo " 二维码（订阅 URL）:"
    qrencode -t ANSIUTF8 "$SUB_URL" || true
fi
echo " 管理: systemctl status aero-edge | journalctl -u aero-edge -f"
echo "========================================="
