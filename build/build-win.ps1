# Mandatory build isolation (Rule N2)
$env:GOWORK = "off"
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist\win"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

$LdFlags = "-s -w"

Write-Host "==> [1/3] Building aero-client.exe (GUI)..." -ForegroundColor Cyan
Push-Location (Join-Path $Root "protocol\client")
go build -ldflags "-s -w -H windowsgui" -o (Join-Path $Dist "aero-client.exe") .\win
Pop-Location

Write-Host "==> [2/3] Building aero-cli.exe..." -ForegroundColor Cyan
Push-Location (Join-Path $Root "protocol\client")
go build -ldflags $LdFlags -o (Join-Path $Dist "aero-cli.exe") .\cli
Pop-Location

Write-Host "==> [3/3] Building aero-guard.exe..." -ForegroundColor Cyan
Push-Location (Join-Path $Root "protocol\client")
go build -ldflags $LdFlags -o (Join-Path $Dist "aero-guard.exe") .\win\guard
Pop-Location

Write-Host "==> Windows build completed successfully in $Dist" -ForegroundColor Green

