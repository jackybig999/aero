# AERO Windows 简易连接（P1）
# 用法:
#   .\connect.ps1 -Sub "https://edge.example.com/sub/SECRET"
#   .\connect.ps1 -Edge "1.2.3.4:443" -Token "your-token"
#   .\connect.ps1 -Config "D:\path\client.yaml"
param(
  [string]$Sub = "",
  [string]$Edge = "",
  [string]$Token = "",
  [string]$Config = "",
  [string]$Listen = "127.0.0.1:55555",
  [string]$Sni = "cdn-aero.com",
  [switch]$Insecure
)

$ErrorActionPreference = "Stop"
$Win = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Client = (Resolve-Path (Join-Path $Win "..")).Path
$Bin = Join-Path $Win "aerowin.exe"
if (-not (Test-Path $Bin)) {
  $Bin = Join-Path $Win "internal\aero-ech.exe"
}

function Ensure-Binary {
  if (Test-Path $Bin) { return }
  Write-Host ">> build aerowin.exe"
  Push-Location $Win
  & go build -o aerowin.exe .
  Pop-Location
  $script:Bin = Join-Path $Win "aerowin.exe"
  if (-not (Test-Path $Bin)) { throw "build failed: $Bin" }
}

function Stop-Old {
  Get-Process -Name "aerowin","aeroapp","aero-ech" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
}

function Wait-Socks([string]$addr, [int]$sec = 15) {
  $hostPort = $addr -split ":"
  $h = $hostPort[0]; $p = [int]$hostPort[1]
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try {
      $c = New-Object System.Net.Sockets.TcpClient
      $iar = $c.BeginConnect($h, $p, $null, $null)
      if ($iar.AsyncWaitHandle.WaitOne(500) -and $c.Connected) { $c.Close(); return $true }
      $c.Close()
    } catch {}
    Start-Sleep -Milliseconds 400
  }
  return $false
}

Write-Host "=== AERO Connect (Windows) ==="
Ensure-Binary
Stop-Old

$argsList = @("-listen", $Listen)
if ($Insecure) { $argsList += "-insecure" }

if ($Config) {
  if (-not (Test-Path $Config)) { throw "config not found: $Config" }
  $argsList += @("-config", $Config)
} elseif ($Sub) {
  $argsList += @("-sub", $Sub)
} elseif ($Edge -and $Token) {
  $argsList += @("-edge", $Edge, "-token", $Token, "-sni", $Sni)
} else {
  $sample = Join-Path $Client "config\config.yaml"
  Write-Host @"

用法（三选一）:
  1) 订阅:  .\connect.ps1 -Sub "https://your-edge/sub/SECRET"
  2) 直连:  .\connect.ps1 -Edge "ip:443" -Token "TOKEN" [-Sni cdn.example.com]
  3) 配置:  .\connect.ps1 -Config "$sample"

可选: -Listen 127.0.0.1:55555  -Insecure
"@
  exit 1
}

Write-Host ">> start $Bin"
Write-Host "   args: $($argsList -join ' ')"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Bin
$psi.Arguments = ($argsList | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
$psi.WorkingDirectory = $Win
$psi.UseShellExecute = $true
$psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized
$proc = [System.Diagnostics.Process]::Start($psi)

if (-not (Wait-Socks $Listen 20)) {
  Write-Host "FAIL: mixed port not ready on $Listen (check edge/token/network)"
  exit 2
}

# Take over Windows system proxy (same as GUI Connect). Mixed port is HTTP+SOCKS5.
try {
  $null = Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:19877/api/v1/mode" -Body '{"mode":"sysproxy"}' -ContentType "application/json" -TimeoutSec 8
  $null = Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:19877/api/v1/connect" -TimeoutSec 8
  Write-Host ">> system proxy ON -> $Listen"
} catch {
  Write-Host "WARN: Control API connect failed: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "========================================"
Write-Host "  CONNECTED"
Write-Host "  MIXED:   $Listen  (HTTP CONNECT + SOCKS5)"
Write-Host "  PID:     $($proc.Id)"
Write-Host "  系统代理已接管；浏览器无需再设"
Write-Host "  AI 工具: HTTP_PROXY=http://$Listen"
Write-Host "  停止:    .\stop.ps1"
Write-Host "========================================"
