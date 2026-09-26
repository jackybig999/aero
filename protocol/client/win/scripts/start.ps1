# Start AERO Windows app (double-click equivalent).
$ErrorActionPreference = "Stop"
$Win = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$App = Join-Path $Win "aerowin.exe"
if (-not (Test-Path $App)) {
  $App = Join-Path $Win "aeroapp.exe"
}
if (-not (Test-Path $App)) {
  Write-Host ">> building aerowin.exe..."
  Push-Location $Win; go build -o aerowin.exe .; Pop-Location
  $App = Join-Path $Win "aerowin.exe"
}
if (-not (Test-Path $App)) { throw "missing $App — build: cd ..\win; go build -o aerowin.exe ." }
Start-Process -FilePath $App -WorkingDirectory $Win
Write-Host "started $App"
