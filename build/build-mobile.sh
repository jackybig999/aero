#!/usr/bin/env bash
# Mandatory build isolation (Rule N2)
export GOWORK=off
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist/mobile"
mkdir -p "${DIST}"

LDFLAGS="-s -w"

echo "==> [1/2] Verifying Mobile SDK cross-compilation..."
cd "${ROOT}/protocol/client"
GOOS=android GOARCH=arm64 go build -ldflags "${LDFLAGS}" ./mobile
GOOS=darwin GOARCH=arm64 go build -ldflags "${LDFLAGS}" ./mobile

echo "==> [2/2] gomobile bind target (AeroKit)..."
if command -v gomobile >/dev/null 2>&1; then
    gomobile bind -target=android -ldflags="${LDFLAGS}" -o "${DIST}/AeroKit.aar" ./mobile
    gomobile bind -target=ios -ldflags="${LDFLAGS}" -o "${DIST}/AeroKit.xcframework" ./mobile
    echo "==> Mobile SDK artifacts generated successfully in ${DIST}"
else
    echo "==> gomobile not found in PATH; Go cross-compilation verified successfully."
fi
