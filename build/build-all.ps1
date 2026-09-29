# Copyright 2026 AERO Protocol Contributors
# AEROSYS 跨平台全量标准构建脚本 (Windows, Linux, macOS, Android/iOS)
# 严格对齐命名规范：aerosys-<component>-<os>-<arch>[.exe]，版本重置为 1.0.0
$env:GOWORK = "off"
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist"
$LdFlags = "-s -w -X 'github.com/aero-protocol/aero-edge/public.Version=1.0.0' -X 'github.com/aero-protocol/aero-ech/public.Version=1.0.0'"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   AEROSYS v1.0.0 Multi-Platform Unified Build System   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Windows 构建
$DistWin = Join-Path $Dist "win"
New-Item -ItemType Directory -Force -Path $DistWin | Out-Null
Write-Host "==> [Windows] Compiling Windows binaries..." -ForegroundColor Yellow

Push-Location (Join-Path $Root "protocol\client")
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -ldflags "-s -w -H windowsgui" -o (Join-Path $DistWin "aerosys-client-windows-amd64.exe") .\win
go build -ldflags $LdFlags -o (Join-Path $DistWin "aerosys-cli-windows-amd64.exe") .\cli
go build -ldflags $LdFlags -o (Join-Path $DistWin "aerosys-guard-windows-amd64.exe") .\win\guard
Pop-Location

# 复制 wintun.dll
if (Test-Path (Join-Path $Root "protocol\client\win\wintun.dll")) {
    Copy-Item -Force (Join-Path $Root "protocol\client\win\wintun.dll") (Join-Path $DistWin "wintun.dll")
}

# 2. Linux 构建 (服务端 Edge + 客户端 CLI)
$DistLinux = Join-Path $Dist "linux"
New-Item -ItemType Directory -Force -Path $DistLinux | Out-Null
Write-Host "==> [Linux] Compiling Linux Edge Server & Client binaries..." -ForegroundColor Yellow

# Linux amd64 & arm64 Server
Push-Location (Join-Path $Root "protocol\server")
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -ldflags $LdFlags -o (Join-Path $DistLinux "aerosys-server-linux-amd64") .\vps
$env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
go build -ldflags $LdFlags -o (Join-Path $DistLinux "aerosys-server-linux-arm64") .\vps
Pop-Location

# Linux amd64 & arm64 Client
Push-Location (Join-Path $Root "protocol\client")
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -ldflags $LdFlags -o (Join-Path $DistLinux "aerosys-client-linux-amd64") .\cli
$env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
go build -ldflags $LdFlags -o (Join-Path $DistLinux "aerosys-client-linux-arm64") .\cli
Pop-Location

# 3. macOS 构建 (客户端 arm64 Apple Silicon + amd64 Intel)
$DistMac = Join-Path $Dist "mac"
New-Item -ItemType Directory -Force -Path $DistMac | Out-Null
Write-Host "==> [macOS] Compiling macOS Client binaries..." -ForegroundColor Yellow

Push-Location (Join-Path $Root "protocol\client")
$env:GOOS = "darwin"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
go build -ldflags $LdFlags -o (Join-Path $DistMac "aerosys-client-darwin-arm64") .\mac
$env:GOOS = "darwin"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -ldflags $LdFlags -o (Join-Path $DistMac "aerosys-client-darwin-amd64") .\mac
Pop-Location

# 清理环境变量
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""

Write-Host "==> [CLEANUP] Cleaning temporary cache files from dist/..." -ForegroundColor Yellow
Get-ChildItem -Path $Dist -Include "*.json","*.log","*.last-sub-body" -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   BUILD FINISHED: All binaries structured and ready in dist/   " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
