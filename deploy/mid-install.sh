#!/bin/bash
# AERO Midplatform (aero-mid) Linux VPS 一键部署脚本
set -e

PORT=${PORT:-18080}
BIN="/usr/local/bin/aero-mid"
DATA_DIR="/opt/aero/data"
CONFIG_DIR="/opt/aero/config"

echo "=== AERO Midplatform Control Plane (aero-mid) Installer ==="

mkdir -p "$DATA_DIR" "$CONFIG_DIR" /var/log

# Copy binary if present in current directory
if [ -f "./aero-mid" ]; then
    cp -f ./aero-mid "$BIN"
    chmod +x "$BIN"
elif [ -f "./subvps" ]; then
    cp -f ./subvps "$BIN"
    chmod +x "$BIN"
elif [ -f "../aero-mid" ]; then
    cp -f ../aero-mid "$BIN"
    chmod +x "$BIN"
else
    echo ">> Building aero-mid from source..."
    if [ -d "./aerosub/cmd/mid" ]; then
        go build -o "$BIN" ./aerosub/cmd/mid
    elif [ -d "./cmd/mid" ]; then
        go build -o "$BIN" ./cmd/mid
    fi
    chmod +x "$BIN"
fi

# Copy SNI matrix if present
if [ -f "./deploy/sni_matrix.json" ]; then
    cp -f ./deploy/sni_matrix.json "$DATA_DIR/sni_matrix.json"
elif [ -f "./sni_matrix.json" ]; then
    cp -f ./sni_matrix.json "$DATA_DIR/sni_matrix.json"
fi

# Copy web UI assets if present
if [ -d "./aerosub/cmd/mid/web" ]; then
    mkdir -p /opt/aero/web
    cp -rf ./aerosub/cmd/mid/web/* /opt/aero/web/
elif [ -d "./cmd/mid/web" ]; then
    mkdir -p /opt/aero/web
    cp -rf ./cmd/mid/web/* /opt/aero/web/
elif [ -d "./web" ]; then
    mkdir -p /opt/aero/web
    cp -rf ./web/* /opt/aero/web/
fi

# Setup systemd service
cat > /etc/systemd/system/aero-mid.service << EOF
[Unit]
Description=AERO Midplatform Control Plane Service
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=/opt/aero
Environment="PORT=${PORT}"
Environment="DATA_DIR=${DATA_DIR}"
Environment="HMAC_SECRET=dev-secret-change-me"
ExecStart=${BIN} -port ${PORT} -data ${DATA_DIR}
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aero-mid
systemctl restart aero-mid

echo ">> aero-mid service started successfully on port ${PORT}"
systemctl status aero-mid --no-pager
