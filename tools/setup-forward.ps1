# Read /data/local/tmp/.listen from device and configure adb forward.
param(
    [int]$Port = 0,
    [string]$Device = "",
    [ValidateSet("auto", "unix", "tcp")]
    [string]$Mode = "auto"
)

$ErrorActionPreference = "Stop"

function Invoke-Adb {
    param([string[]]$AdbArguments)
    $adbArgs = @()
    if ($Device) { $adbArgs += @("-s", $Device) }
    & adb @adbArgs @AdbArguments
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed: $($AdbArguments -join ' ')"
    }
}

$metaRaw = Invoke-Adb @("shell", "su", "-c", "cat /data/local/tmp/.listen 2>/dev/null || true")
$meta = @{}
foreach ($line in ($metaRaw -split "`n")) {
    $line = $line.Trim()
    if ($line -match '^([^=]+)=(.*)$') {
        $meta[$Matches[1]] = $Matches[2]
    }
}

if (-not $meta.mode) {
    Write-Error "No /data/local/tmp/.listen on device — start server with frida-launcher-v2.sh first"
}

$listenMode = if ($Mode -eq "auto") { $meta.mode } else { $Mode }
$forwardPort = if ($Port -gt 0) { $Port } else { [int]$meta.forward_port }
if ($forwardPort -le 0) { $forwardPort = 27100 }

Invoke-Adb @("forward", "--remove-all")

if ($listenMode -eq "unix") {
    $socket = $meta.socket
    if (-not $socket) {
        Write-Error "unix mode but socket name missing in .listen"
    }
    Write-Host "[*] adb forward tcp:$forwardPort localabstract:$socket"
    Invoke-Adb @("forward", "tcp:$forwardPort", "localabstract:$socket")
} else {
    Write-Host "[*] adb forward tcp:$forwardPort tcp:$forwardPort"
    Invoke-Adb @("forward", "tcp:$forwardPort", "tcp:$forwardPort")
}

Write-Host "[*] Ready: frida -H 127.0.0.1:$forwardPort ..."
