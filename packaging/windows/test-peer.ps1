$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Data = Join-Path $env:USERPROFILE ".nexxus-rs"
$Log = Join-Path $Root "lab-test.log"
$Bin = Join-Path $env:LOCALAPPDATA "NeXXuS\nexxus.exe"
if (-not (Test-Path $Bin)) { $Bin = Join-Path $Root "nexxus.exe" }
if ($args.Count -lt 1) { "нужен контакт второй ноды" | Tee-Object -FilePath $Log -Append; exit 2 }
$Contact = $args[0]
$Fp = $Contact.Split(":")[2]
$Hello = Join-Path $Data "lab-hello.txt"
New-Item -ItemType Directory -Force -Path $Data | Out-Null
"nexxus-lab $env:COMPUTERNAME" | Set-Content -Path $Hello -Encoding ascii
function Run($cmd) {
  "ctl $cmd" | Tee-Object -FilePath $Log -Append
  & $Bin ctl --data $Data $cmd 2>&1 | Tee-Object -FilePath $Log -Append
}
"when $(Get-Date -Format o)" | Tee-Object -FilePath $Log -Append
Run "dial $Contact"
Run "put $Hello"
Start-Sleep -Seconds 1
Run "chat $Fp hello from $env:COMPUTERNAME"
Start-Sleep -Seconds 3
Run "status"
Run "files"
Run "chats"
