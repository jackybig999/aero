#!/usr/bin/env bash
# Mandatory build isolation (Rule N2)
export GOWORK=off
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist/mac"
mkdir -p "${DIST}"

LDFLAGS="-s -w"

echo "==> [1/2] Building aeromac (macOS)..."
cd "${ROOT}/protocol/client"
GOOS=darwin GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o "${DIST}/aeromac-arm64" ./mac
GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o "${DIST}/aeromac-amd64" ./mac

echo "==> [2/2] Building desktop-mac..."
cd "${ROOT}/connect/desktop"
GOOS=darwin GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o "${DIST}/desktop-mac-arm64" ./mac
GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o "${DIST}/desktop-mac-amd64" ./mac

echo "==> macOS build completed successfully in ${DIST}"
