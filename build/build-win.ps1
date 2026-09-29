# Mandatory build isolation (Rule N2)
$env:GOWORK = "off"
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist\win"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

$LdFlags = "-s -w"

Write-Host "==> [1/3] Building aerosys-client-windows-amd64.exe (GUI)..." -ForegroundColor Cyan
Push-Location (Join-Path $Root "protocol\client")
go build -ldflags "-s -w -H windowsgui" -o (Join-Path $Dist "aerosys-client-windows-amd64.exe") .\win
Pop-Location

Write-Host "==> [2/3] Building aerosys-cli-windows-amd64.exe..." -ForegroundColor Cyan
Push-Location (Join-Path $Root "protocol\client")
go build -ldflags $LdFlags -o (Join-Path $Dist "aerosys-cli-windows-amd64.exe") .\cli
Pop-Location

Write-Host "==> [3/3] Building aerosys-guard-windows-amd64.exe..." -ForegroundColor Cyan
Push-Location (Join-Path $Root "protocol\client")
go build -ldflags $LdFlags -o (Join-Path $Dist "aerosys-guard-windows-amd64.exe") .\win\guard
Pop-Location

# Bundle wintun.dll next to binaries
if (Test-Path (Join-Path $Root "protocol\client\win\wintun.dll")) {
    Copy-Item -Force (Join-Path $Root "protocol\client\win\wintun.dll") (Join-Path $Dist "wintun.dll")
}

Write-Host "==> Windows build completed successfully in $Dist" -ForegroundColor Green

