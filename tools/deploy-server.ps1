# Deploy anti-detection frida-server to a rooted Android device.
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerPath,

    [int]$Port = 27100,

    [string]$Device = "",

    [switch]$CleanTmp,

    [ValidateSet("unix", "tcp")]
    [string]$ListenMode = "unix"
)

$ErrorActionPreference = "Stop"
$ToolsDir = $PSScriptRoot
$Launcher = Join-Path $ToolsDir "frida-launcher-v2.sh"
$CleanScript = Join-Path $ToolsDir "clean-tmp.sh"
$SetupForward = Join-Path $ToolsDir "setup-forward.ps1"

if (-not (Test-Path $ServerPath)) {
    Write-Error "Server binary not found: $ServerPath"
}

if (-not (Test-Path $Launcher)) {
    Write-Error "Launcher not found: $Launcher"
}

function Invoke-Adb {
    param([string[]]$AdbArguments)
    $adbArgs = @()
    if ($Device) { $adbArgs += @("-s", $Device) }
    & adb @adbArgs @AdbArguments
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed: adb $($adbArgs -join ' ') $($AdbArguments -join ' ')"
    }
}

$RemoteBin = "/data/local/tmp/." + (-join ((48..57) + (97..102) | Get-Random -Count 8 | ForEach-Object { [char]$_ }))
$RemoteLauncher = "/data/local/tmp/.ks"

Write-Host "[*] Pushing server and launcher..."
Invoke-Adb @("push", $ServerPath, $RemoteBin)
Invoke-Adb @("push", $Launcher, $RemoteLauncher)
Invoke-Adb @("push", $CleanScript, "/data/local/tmp/clean-tmp.sh")

if ($CleanTmp) {
    Write-Host "[*] Quarantining old tmp artifacts..."
    Invoke-Adb @("shell", "su", "-c", "sh /data/local/tmp/clean-tmp.sh")
}

Write-Host "[*] Starting stealth server (LISTEN_MODE=$ListenMode, host forward port $Port) ..."
Invoke-Adb @(
    "shell",
    "su",
    "-c",
    "chmod 700 $RemoteBin $RemoteLauncher; USE_CMDLINE_LISTEN=0 LISTEN_MODE=$ListenMode nohup sh $RemoteLauncher $RemoteBin $Port >/data/local/tmp/.launcher.log 2>&1 &"
)

Start-Sleep -Seconds 3

$log = Invoke-Adb @("shell", "su", "-c", "cat /data/local/tmp/.launcher.log 2>/dev/null || true")
if ($log) { Write-Host $log }

if ($Device) {
    & $SetupForward -Port $Port -Mode $ListenMode -Device $Device
} else {
    & $SetupForward -Port $Port -Mode $ListenMode
}

Write-Host ""
Write-Host "Ready. Example:"
Write-Host "  .\tools\run-frida-patched.ps1 frida-ps -H 127.0.0.1:$Port"
Write-Host "  .\tools\run-frida-patched.ps1 frida -H 127.0.0.1:$Port -n com.ubrmb.app -e `"console.log('ok')`""
