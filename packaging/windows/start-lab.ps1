$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Data = Join-Path $env:USERPROFILE ".nexxus-rs"
$Bin = Join-Path $env:LOCALAPPDATA "NeXXuS\nexxus.exe"
if (-not (Test-Path $Bin)) { $Bin = Join-Path $Root "nexxus.exe" }
New-Item -ItemType Directory -Force -Path $Data | Out-Null
Write-Host "Старт. Журнал: $Data\node.log"
& $Bin start --data $Data --listen 0.0.0.0 --port 4377 --name $env:COMPUTERNAME
