#!/bin/bash
# Subplatform (vpsserver / subvps) Linux VPS 一键安装脚本
set -e

PORT=${PORT:-18080}
BIN="/usr/local/bin/subvps"
DATA_DIR="/opt/vpn/data"
CONFIG_DIR="/opt/vpn/config"

echo "=== AIsys Subscription Platform (subvps) Installer ==="

mkdir -p /opt/vpn/data /opt/vpn/config /var/log

# Copy binary if present in current directory
if [ -f "./subvps" ]; then
    cp -f ./subvps "$BIN"
    chmod +x "$BIN"
elif [ -f "../subvps" ]; then
    cp -f ../subvps "$BIN"
    chmod +x "$BIN"
else
    echo ">> Building subvps from source..."
    go build -o "$BIN" .
    chmod +x "$BIN"
fi

# Copy default config if missing
if [ ! -f "$CONFIG_DIR/config.yaml" ] && [ -f "../config/config.yaml" ]; then
    cp -f ../config/config.yaml "$CONFIG_DIR/config.yaml"
fi

# Setup systemd service
cat > /etc/systemd/system/subvps.service << EOF
[Unit]
Description=AIsys Subscription Platform Service
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=/opt/vpn
Environment="PORT=${PORT}"
Environment="DATA_DIR=${DATA_DIR}"
Environment="HMAC_SECRET=dev-secret-change-me"
ExecStart=${BIN}
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable subvps
systemctl restart subvps

echo ">> subvps service started successfully on port ${PORT}"
systemctl status subvps --no-pager
