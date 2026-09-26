# Undo leftover AERO proxy / DNS / routes / firewall. Safe to run while using box.
$ErrorActionPreference = "SilentlyContinue"
Get-Process aero-ech,aeroapp,aero-guard -ErrorAction SilentlyContinue | Stop-Process -Force
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f
netsh winhttp reset proxy | Out-Null
foreach ($k in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','NO_PROXY')) {
  [Environment]::SetEnvironmentVariable($k, $null, 'User')
}
netsh interface set interface name="aero0" admin=DISABLED | Out-Null
route delete 0.0.0.0 mask 128.0.0.0
route delete 128.0.0.0 mask 128.0.0.0
route delete 128.241.228.161
foreach ($n in @('AERO-NoQUIC-all','AERO-NoQUIC-chrome','AERO-NoQUIC-edge','AERO-NoQUIC-brave','AERO-NoQUIC-chromium','AERO-NoIPv6')) {
  netsh advfirewall firewall delete rule name=$n | Out-Null
}
$ifaces = netsh interface ipv4 show interfaces
foreach ($line in ($ifaces -split "`n")) {
  if ($line -notmatch 'connected' -or $line -match 'disconnected') { continue }
  $fields = $line.Trim() -split '\s+'
  if ($fields.Count -lt 5) { continue }
  $name = $fields[4]
  if ($name -match 'Loopback|singbox|meta|mihomo|clash|aero') { continue }
  netsh interface ip set dns name="$name" dhcp | Out-Null
}
ipconfig /flushdns | Out-Null
Write-Host "AERO leftovers cleared. Physical DNS set back to DHCP."
