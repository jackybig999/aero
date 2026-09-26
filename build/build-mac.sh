#!/usr/bin/env bash
# Mandatory build isolation (Rule N2)
export GOWORK=off
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist/mac"
mkdir -p "${DIST}"

LDFLAGS="-s -w"

echo "==> [1/2] Building aero-cli (macOS arm64 & amd64)..."
cd "${ROOT}/protocol/client"
GOOS=darwin GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o "${DIST}/aero-cli-darwin-arm64" ./cli
GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o "${DIST}/aero-cli-darwin-amd64" ./cli

echo "==> [2/2] Building aeromac (macOS GUI)..."
cd "${ROOT}/protocol/client"
GOOS=darwin GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o "${DIST}/aeromac-arm64" ./mac
GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o "${DIST}/aeromac-amd64" ./mac

echo "==> macOS build completed successfully in ${DIST}"

