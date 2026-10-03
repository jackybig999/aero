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
VERSION="1.0.1"
REPO="jackybig999/aero"

usage() {
    echo "AERO Edge 一键安装"
    echo "  -d, --domain DOMAIN     域名（必须；ACME HTTP-01 需 :80 可达）"
    echo "  -i, --ip IP             写入订阅的备用公网 IP（有域名时可选）"
    echo "  -t, --token TOKEN       可选，默认自动生成"
    echo "  -e, --email EMAIL       ACME 邮箱（默认 admin@DOMAIN）"
    echo "  -p, --ports PORTS       监听端口，默认 443（可改，如 443 或 8443）"
    echo "  -s, --sni SNI           TLS SNI（默认 = 域名）"
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

detect_best_https_port() {
    local preferred="$1"
    local candidates=("$preferred" 443 8443 2053 2083 2087 2096)
    local tested=" "
    for p in "${candidates[@]}"; do
        if [[ "$tested" =~ " ${p} " ]]; then
            continue
        fi
        tested+="${p} "

        local in_use=0
        if command -v ss >/dev/null 2>&1; then
            if ss -tlpn 2>/dev/null | grep -E ":$p\b" | grep -qv "aero-edge"; then
                in_use=1
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -tlpn 2>/dev/null | grep -E ":$p\b" | grep -qv "aero-edge"; then
                in_use=1
            fi
        elif command -v fuser >/dev/null 2>&1; then
            if fuser "$p/tcp" >/dev/null 2>&1; then
                in_use=1
            fi
        fi

        if [[ "$in_use" -eq 0 ]]; then
            echo "$p"
            return 0
        fi
    done
    echo "$preferred"
}

ADVERTISE_HOST="${DOMAIN:-$ADVERTISE_IP}"
PRIMARY_PORT=$(echo "$PORTS" | cut -d, -f1 | tr -d ' ')
if [[ "$PRIMARY_PORT" == "443" || "$PRIMARY_PORT" == "auto" || -z "$PRIMARY_PORT" ]]; then
    systemctl stop aero-edge 2>/dev/null || true
    BEST_PORT=$(detect_best_https_port 443)
    if [[ "$BEST_PORT" != "443" ]]; then
        echo "[port] 443 端口被其他服务占用 (如 sing-box/s-ui/nginx)，自动优选标准 HTTPS 备用端口: ${BEST_PORT}"
        PRIMARY_PORT="$BEST_PORT"
        PORTS="$BEST_PORT"
    else
        PRIMARY_PORT="443"
        PORTS="443"
    fi
fi

CERT="$TLS_DIR/fullchain.pem"
KEY="$TLS_DIR/privkey.pem"

echo "========================================="
echo " AERO Edge v${VERSION}"
echo " domain:    $DOMAIN"
echo " advertise: $ADVERTISE_HOST"
echo " ports:     $PORTS (active/selected)"
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

# --- binary: backup existing for rollback ---
echo "[bin] install aeroprot-edge -> $INSTALL_DIR/aero-edge"
if [[ -f "$INSTALL_DIR/aero-edge" ]]; then
    cp -f "$INSTALL_DIR/aero-edge" "$INSTALL_DIR/aero-edge.bak" 2>/dev/null || true
fi

BINARY_URL="https://github.com/${REPO}/releases/download/v${VERSION}/aeroprot-edge-linux-${ARCH}"
LATEST_URL="https://github.com/${REPO}/releases/latest/download/aeroprot-edge-linux-${ARCH}"
installed_ok=0

if command -v curl >/dev/null 2>&1; then
    if curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/aeroprot-edge" 2>/dev/null; then
        echo "[bin] 成功从官方 Release (v${VERSION}) 拉取服务端二进制产物。"
        installed_ok=1
    elif curl -fsSL "$LATEST_URL" -o "$INSTALL_DIR/aeroprot-edge" 2>/dev/null; then
        echo "[bin] 成功从官方最新 Release 拉取服务端二进制产物。"
        installed_ok=1
    fi
fi

if [[ "$installed_ok" -eq 0 ]]; then
    echo "[bin] 官方 Release 资产未就绪，正在从官方公开仓库源码构建..."
    TMP_SRC=$(mktemp -d /tmp/aero-src-XXXXXX)
    if git clone --depth 1 "https://github.com/${REPO}.git" "$TMP_SRC"; then
        if ! command -v go >/dev/null 2>&1; then
            echo "[bin] 目标主机缺少 go 编译器，正在自动安装..."
            apt-get update -y && apt-get install -y golang-go >/dev/null 2>&1 || yum install -y golang >/dev/null 2>&1 || true
        fi
        if [[ -d "$TMP_SRC/aeroprot/cmd/edge" ]]; then
            (cd "$TMP_SRC" && go build -v -ldflags="-s -w" -o "$INSTALL_DIR/aeroprot-edge" ./aeroprot/cmd/edge)
        elif [[ -d "$TMP_SRC/cmd/edge" ]]; then
            (cd "$TMP_SRC" && go build -v -ldflags="-s -w" -o "$INSTALL_DIR/aeroprot-edge" ./cmd/edge)
        elif [[ -d "$TMP_SRC/protocol/server/vps" ]]; then
            (cd "$TMP_SRC/protocol/server/vps" && go build -v -ldflags="-s -w" -o "$INSTALL_DIR/aeroprot-edge" .)
        fi
        rm -rf "$TMP_SRC"
        echo "[bin] 官方公开源直接构建完成。"
        installed_ok=1
    else
        echo "[bin] 错误: 无法从官方公开源拉取发布包或源码: https://github.com/${REPO}"
        rm -rf "$TMP_SRC"
        exit 1
    fi
fi
chmod 755 "$INSTALL_DIR/aeroprot-edge"
ln -sf "$INSTALL_DIR/aeroprot-edge" "$INSTALL_DIR/aero-edge"

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
    for d in "/root/cert/${DOMAIN}" "/root/certs/${DOMAIN}" "/root/cert" "/root/certs" "/root/.acme.sh/${DOMAIN}_ecc" "/root/.acme.sh/${DOMAIN}" "/etc/letsencrypt/live/${DOMAIN}" "/etc/cert/${DOMAIN}" "/etc/certs/${DOMAIN}"; do
        FC=""
        [[ -f "$d/fullchain.cer" ]] && FC="$d/fullchain.cer"
        [[ -f "$d/fullchain.pem" ]] && FC="$d/fullchain.pem"
        [[ -f "$d/${DOMAIN}.cer" ]] && FC="$d/${DOMAIN}.cer"
        KY=""
        [[ -f "$d/privkey.pem" ]] && KY="$d/privkey.pem"
        [[ -f "$d/${DOMAIN}.key" ]] && KY="$d/${DOMAIN}.key"
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

# --- firewall: open PRIMARY_PORT & 80 ---
echo "[firewall] 放行业务端口 TCP ${PRIMARY_PORT} 与 ACME TCP 80"
if command -v ufw >/dev/null 2>&1; then
    ufw allow "${PRIMARY_PORT}/tcp" 2>/dev/null || true
    ufw allow 80/tcp 2>/dev/null || true
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport "${PRIMARY_PORT}" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
fi
# --- sysctl: 固化 BBRv3、FQ 队列与 128MB TCP 跨洋流控窗口 (Rule Phase 4.5 & L6) ---
echo "[sysctl] 优化 BBR 拥塞控制与 128MB TCP 缓冲区"
cat > /etc/sysctl.d/99-aero-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_mtu_probing = 1
net.core.netdev_max_backlog = 10000
EOF
sysctl --system >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl enable aero-edge
systemctl restart aero-edge

# --- health check & auto-rollback ---
sleep 2
if ! systemctl is-active --quiet aero-edge; then
    echo "[rollback] 启动失败，触发自动回滚..."
    if [[ -f "$INSTALL_DIR/aero-edge.bak" ]]; then
        cp -f "$INSTALL_DIR/aero-edge.bak" "$INSTALL_DIR/aero-edge"
        systemctl restart aero-edge
        echo "[rollback] 已成功回滚至上一版本并恢复运行"
    else
        echo "[rollback] 无备份可回滚"
        journalctl -u aero-edge -n 30 --no-pager || true
        exit 1
    fi
fi

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

if [[ "${PRIMARY_PORT}" == "443" ]]; then
    SUB_URL="https://${ADVERTISE_HOST}/sub/${SUB_SECRET}"
else
    SUB_URL="https://${ADVERTISE_HOST}:${PRIMARY_PORT}/sub/${SUB_SECRET}"
fi
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
