#!/usr/bin/env bash
# Mandatory build isolation (Rule N2)
export GOWORK=off
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist/vps"
mkdir -p "${DIST}"

LDFLAGS="-s -w"

echo "==> [1/2] Compiling static Linux amd64 aero-edge..."
cd "${ROOT}/protocol/server"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o "${DIST}/aero-edge-linux-amd64" ./vps

echo "==> [2/2] Compiling static Linux arm64 aero-edge..."
cd "${ROOT}/protocol/server"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o "${DIST}/aero-edge-linux-arm64" ./vps

echo "==> Linux VPS production binaries generated successfully in ${DIST}"

