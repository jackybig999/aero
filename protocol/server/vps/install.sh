#!/bin/bash
# AERO Edge — 一键安装
#
# 证书策略（生产）：
#   1) 已有 /var/lib/aero/tls/{fullchain,privkey}.pem 且未过期 → 跳过
#   2) 否则从 acme.sh / certbot 拷贝
#   3) 否则 acme.sh 签发：Let's Encrypt 首选，ZeroSSL 备选
#   4) 禁止自签证书；失败则退出
#   5) cron 自动续签 + install-cert reload
#
# 端口：默认服务端 443（-p 可改）；客户端默认 55555 见 aero-ech -listen
#
# 用法:
#   bash install.sh -d edge.example.com
#   bash install.sh -d edge.example.com -p 443 -b ./aero-edge
#   bash install.sh -d edge.example.com -e admin@example.com
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
TLS_DIR="/var/lib/aero/tls"
CERT_DIR="/var/lib/aero/certs"
LOG_DIR="/var/log"
VERSION="1.1.0"
REPO="jackybig999/aero"
LOCAL_BIN=""

usage() {
    echo "AERO Edge 一键安装"
    echo "  -d, --domain DOMAIN     域名（必须；ACME HTTP-01 需 :80 可达）"
    echo "  -i, --ip IP             写入订阅的备用公网 IP（有域名时可选）"
    echo "  -t, --token TOKEN       可选，默认自动生成"
    echo "  -e, --email EMAIL       ACME 邮箱（默认 admin@DOMAIN）"
    echo "  -p, --ports PORTS       监听端口，默认 443（可改，如 443 或 8443）"
    echo "  -s, --sni SNI           TLS SNI（默认 = 域名）"
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

if [[ -z "$DOMAIN" ]]; then
    echo "错误: 必须提供 -d DOMAIN（生产环境禁止自签，需公网证书）"
    usage
fi
if [[ -z "$TOKEN" ]]; then
    TOKEN="aero_$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    echo "提示: 已自动生成 token"
fi
if [[ -z "$SNI" ]]; then
    SNI="$DOMAIN"
fi
if [[ -z "$EMAIL" ]]; then
    EMAIL="admin@${DOMAIN}"
fi

ADVERTISE_HOST="${DOMAIN:-$ADVERTISE_IP}"
PRIMARY_PORT=$(echo "$PORTS" | cut -d, -f1 | tr -d ' ')
CERT="$TLS_DIR/fullchain.pem"
KEY="$TLS_DIR/privkey.pem"

echo "========================================="
echo " AERO Edge v${VERSION}"
echo " domain:    $DOMAIN"
echo " advertise: $ADVERTISE_HOST"
echo " ports:     $PORTS (default/preferred 443)"
echo " data:      $DATA_DIR"
echo " tls:       $TLS_DIR"
echo " cert:      LE first, ZeroSSL backup; no self-sign"
echo "========================================="

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="armv7" ;;
esac

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$CERT_DIR" "$TLS_DIR"

# --- edge.conf ---
cat > "$CONFIG_DIR/edge.conf" << CONF
AERO_DATA_DIR=$DATA_DIR
AERO_TOKEN=$TOKEN
AERO_DOMAIN=$DOMAIN
AERO_PORTS=$PORTS
AERO_SNI=$SNI
AERO_ADVERTISE=$ADVERTISE_HOST
CONF
chmod 600 "$CONFIG_DIR/edge.conf"

# --- binary ---
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
            echo "[bin] 请: go build -o aero-edge ./aero-edge/cmd/aero-edge && bash install.sh -b ./aero-edge -d $DOMAIN"
            exit 1
        fi
    else
        echo "需要 curl 或 -b 本地二进制"; exit 1
    fi
    chmod +x "$INSTALL_DIR/aero-edge"
fi

# --- TLS: detect → copy → issue (LE → ZeroSSL) → never self-sign ---
need_issue=1
if [[ -f "$CERT" && -f "$KEY" ]]; then
    if openssl x509 -in "$CERT" -noout -checkend 86400 >/dev/null 2>&1; then
        echo "[cert] CERT_STATUS=existing_ok (skip ACME)"
        need_issue=0
    else
        echo "[cert] CERT_STATUS=existing_expiring"
    fi
fi

if [[ "$need_issue" = "1" ]]; then
    for d in "/root/.acme.sh/${DOMAIN}_ecc" "/root/.acme.sh/${DOMAIN}" "/etc/letsencrypt/live/${DOMAIN}"; do
        FC=""
        [[ -f "$d/fullchain.cer" ]] && FC="$d/fullchain.cer"
        [[ -f "$d/fullchain.pem" ]] && FC="$d/fullchain.pem"
        KY=""
        [[ -f "$d/privkey.pem" ]] && KY="$d/privkey.pem"
        if [[ -z "$KY" ]]; then
            KY=$(ls "$d"/*.key 2>/dev/null | head -1 || true)
        fi
        if [[ -n "$FC" && -n "$KY" && -f "$FC" && -f "$KY" ]]; then
            cp -f "$FC" "$CERT"
            cp -f "$KY" "$KEY"
            chmod 644 "$CERT"; chmod 600 "$KEY"
            echo "[cert] CERT_STATUS=copied_from $d"
            need_issue=0
            break
        fi
    done
fi

if [[ "$need_issue" = "1" ]]; then
    echo "[cert] CERT_STATUS=issuing (need :80 free for HTTP-01)"
    systemctl stop aero-edge 2>/dev/null || true
    # free :80 if something else holds it briefly (best-effort)
    if command -v fuser >/dev/null 2>&1; then
        fuser -k 80/tcp 2>/dev/null || true
    fi

    export HOME=/root
    if [[ ! -f /root/.acme.sh/acme.sh ]]; then
        echo "[cert] installing acme.sh…"
        curl -fsSL https://get.acme.sh | sh -s email="$EMAIL" || true
    fi
    ACME=/root/.acme.sh/acme.sh
    if [[ ! -x "$ACME" ]]; then
        echo "[cert] ERROR: acme.sh missing; refuse self-signed"
        exit 1
    fi

    # Primary: Let's Encrypt
    echo "[cert] try Let's Encrypt…"
    "$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
    "$ACME" --issue -d "$DOMAIN" --standalone --keylength ec-256 --force 2>&1 | tail -30 || true

    if [[ ! -f "/root/.acme.sh/${DOMAIN}_ecc/fullchain.cer" && ! -f "/root/.acme.sh/${DOMAIN}/fullchain.cer" ]]; then
        echo "[cert] LE failed → try ZeroSSL (backup CA)…"
        "$ACME" --set-default-ca --server zerossl >/dev/null 2>&1 || true
        "$ACME" --register-account -m "$EMAIL" >/dev/null 2>&1 || true
        "$ACME" --issue -d "$DOMAIN" --standalone --keylength ec-256 --force 2>&1 | tail -30 || true
    fi

    issued=0
    for d in "/root/.acme.sh/${DOMAIN}_ecc" "/root/.acme.sh/${DOMAIN}"; do
        if [[ -f "$d/fullchain.cer" ]]; then
            cp -f "$d/fullchain.cer" "$CERT"
            cp -f "$(ls "$d"/*.key | head -1)" "$KEY"
            chmod 644 "$CERT"; chmod 600 "$KEY"
            echo "[cert] CERT_STATUS=issued_ok from $d"
            "$ACME" --install-cert -d "$DOMAIN" --ecc \
                --fullchain-file "$CERT" --key-file "$KEY" \
                --reloadcmd "systemctl reload aero-edge 2>/dev/null || systemctl restart aero-edge" 2>/dev/null \
              || "$ACME" --install-cert -d "$DOMAIN" \
                --fullchain-file "$CERT" --key-file "$KEY" \
                --reloadcmd "systemctl restart aero-edge" 2>/dev/null || true
            issued=1
            break
        fi
    done
    if [[ "$issued" != "1" ]]; then
        echo "[cert] CERT_STATUS=FAILED_no_public_cert"
        echo "ERROR: 无法签发公网证书。请确认："
        echo "  - 域名 $DOMAIN A 记录指向本机"
        echo "  - 防火墙放行 TCP 80（ACME）与 $PRIMARY_PORT（业务）"
        echo "  - 或手动放置 PEM: $CERT + $KEY"
        echo "禁止使用自签证书。"
        exit 1
    fi
fi

if [[ -f "$CERT" ]]; then
    openssl x509 -in "$CERT" -noout -issuer -subject -dates 2>/dev/null | sed 's/^/[cert] /' || true
fi

# cron renew（acme.sh 自带；再保险一条）
crontab -l 2>/dev/null | grep -q acme.sh || (
    crontab -l 2>/dev/null
    echo "0 3 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh > /dev/null"
) | crontab - 2>/dev/null || true

# --- systemd: static LE/ZeroSSL PEMs only（-cert/-key），不走 -autocert 自签回退 ---
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
EnvironmentFile=-$CONFIG_DIR/edge.conf
ExecStart=$INSTALL_DIR/aero-edge \\
  -token $TOKEN \\
  -listen :${PRIMARY_PORT} \\
  -ports ${PORTS} \\
  -profile small \\
  -data-dir $DATA_DIR \\
  -domain $DOMAIN \\
  -sni $SNI \\
  -advertise-host $ADVERTISE_HOST \\
  -cert $CERT \\
  -key $KEY \\
  -log-file $LOG_DIR/aero-edge.log \\
  -q
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
cp -f "$DATA_DIR/client-sub.json" "$CONFIG_DIR/client-sub.json" 2>/dev/null || true

SUB_URL="https://${ADVERTISE_HOST}:${PRIMARY_PORT}/sub/${SUB_SECRET}"
if [[ -z "$SUB_SECRET" ]]; then
    SUB_URL="(见 $DATA_DIR/sub_meta.json)"
fi

echo ""
echo "========================================="
echo " 安装完成 — 客户端一键导入"
echo "========================================="
echo " Token:      $TOKEN"
echo " Listen:     :${PRIMARY_PORT} (可 -p 自定义)"
echo " Cert:       $CERT (public CA, auto-renew)"
echo " Data dir:   $DATA_DIR"
echo " Sub URL:    $SUB_URL"
echo ""
echo " 客户端（本机混合口默认 55555，可 -listen 改）:"
echo "   aero-ech -sub $SUB_URL -listen 127.0.0.1:55555"
echo "   浏览器/软件代理设为 127.0.0.1:55555（HTTP 或 SOCKS5）"
echo "   不改 Windows 注册表 / 系统代理"
echo ""
echo " 管理: systemctl status aero-edge | journalctl -u aero-edge -f"
echo "========================================="
