# AIsys Unified Asset Distribution Script
# Syncs branding assets from /assets to all subsystem targets

$ErrorActionPreference = "Stop"

$RootDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($RootDir) -or -not (Test-Path (Join-Path $RootDir "assets"))) {
    $RootDir = (Get-Location).Path
}

$AssetsDir = Join-Path $RootDir "assets"
if (-not (Test-Path $AssetsDir)) {
    Write-Error "Asset root not found: $AssetsDir"
    exit 1
}

Write-Host "=== AIsys Brand & Asset Distribution Pipeline ===" -ForegroundColor Cyan
Write-Host "Source: $AssetsDir" -ForegroundColor Cyan

$IcoSrc = Join-Path $AssetsDir "icon.ico"
$IcnsSrc = Join-Path $AssetsDir "icon.icns"
$PngSrc = Join-Path $AssetsDir "icon.png"
$PngMasterSrc = Join-Path $AssetsDir "icon-1024.png"

# 1. Windows / Client Public Engine
$ClientPublicAssets = Join-Path $RootDir "protocol\client\public\assets"
if (Test-Path $ClientPublicAssets) {
    Copy-Item -Path $IcoSrc -Destination (Join-Path $ClientPublicAssets "app.ico") -Force
    if (Test-Path $PngMasterSrc) {
        Copy-Item -Path $PngMasterSrc -Destination (Join-Path $ClientPublicAssets "app.png") -Force
    }
    Write-Host "[OK] Synced protocol/client/public/assets (app.ico, app.png)" -ForegroundColor Green
}

$ClientWin = Join-Path $RootDir "protocol\client\win"
if (Test-Path $ClientWin) {
    Copy-Item -Path $IcoSrc -Destination (Join-Path $ClientWin "aeroapp.ico") -Force
    Write-Host "[OK] Synced protocol/client/win (aeroapp.ico)" -ForegroundColor Green
}

# 2. macOS Client
$ClientMac = Join-Path $RootDir "protocol\client\mac"
if (Test-Path $ClientMac) {
    Copy-Item -Path $IcnsSrc -Destination (Join-Path $ClientMac "icon.icns") -Force
    if (Test-Path $PngMasterSrc) {
        Copy-Item -Path $PngMasterSrc -Destination (Join-Path $ClientMac "icon.png") -Force
    }
    Write-Host "[OK] Synced protocol/client/mac (icon.icns, icon.png)" -ForegroundColor Green
}

# 3. Linux Client
$ClientLinux = Join-Path $RootDir "protocol\client\linux"
if (Test-Path $ClientLinux) {
    if (Test-Path $PngMasterSrc) {
        Copy-Item -Path $PngMasterSrc -Destination (Join-Path $ClientLinux "icon.png") -Force
    }
    Write-Host "[OK] Synced protocol/client/linux (icon.png)" -ForegroundColor Green
}

# 4. Web Panels Favicon (Admin / User / Protocol WebUI)
$WebTargets = @(
    (Join-Path $RootDir "sub\vpn\web\admin\public"),
    (Join-Path $RootDir "sub\vpn\web\user\public"),
    (Join-Path $RootDir "protocol\server\public\webui\public")
)

foreach ($target in $WebTargets) {
    if (Test-Path $target) {
        Copy-Item -Path $IcoSrc -Destination (Join-Path $target "favicon.ico") -Force
        Write-Host "[OK] Synced $target (favicon.ico)" -ForegroundColor Green
    }
}

Write-Host "=== All subsystem assets synchronized successfully! ===" -ForegroundColor Cyan
