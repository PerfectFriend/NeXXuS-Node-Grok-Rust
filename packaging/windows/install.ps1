$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Root "install.log"
$Bin = Join-Path $Root "nexxus.exe"
function Write-Log($text) {
  $text | Tee-Object -FilePath $Log -Append
}
if (Test-Path $Log) { Remove-Item $Log }
Write-Log ("when " + (Get-Date -Format o))
Write-Log ("user " + $env:USERNAME)
Write-Log ("os " + [Environment]::OSVersion.VersionString)
if (-not (Test-Path $Bin)) {
  $Source = Join-Path $Root "source"
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Log "err нет nexxus.exe и нет cargo. Поставьте Rust с https://rustup.rs и снова запустите install.ps1."
    exit 1
  }
  if (-not (Test-Path $Source)) {
    Write-Log "err нет nexxus.exe и нет каталога source."
    exit 1
  }
  Write-Log "собираю nexxus.exe из source"
  Push-Location $Source
  cargo build --release -p nexxus
  Copy-Item (Join-Path $Source "target\release\nexxus.exe") $Bin -Force
  Pop-Location
}
$DestDir = Join-Path $env:LOCALAPPDATA "NeXXuS"
New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
Copy-Item $Bin (Join-Path $DestDir "nexxus.exe") -Force
Write-Log ("BIN=" + (Join-Path $DestDir "nexxus.exe"))
& $Bin version | Tee-Object -FilePath $Log -Append
Write-Log "OK"
