Get-Process -Name "aerowin","aeroapp","aerocli","aero-ech","aero-guard" -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "AERO processes stopped (if any)"
