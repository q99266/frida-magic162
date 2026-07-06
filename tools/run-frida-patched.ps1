# Run frida CLI with patched re.nginx client (shadow package, no site-packages overwrite).
$ErrorActionPreference = "Stop"
$ShadowRoot = Join-Path $PSScriptRoot "frida-patched"
$ShadowPkg = Join-Path $ShadowRoot "frida"

if (-not (Test-Path (Join-Path $ShadowPkg "_frida.pyd"))) {
    python (Join-Path $PSScriptRoot "patch-frida-client.py") --output-dir $ShadowRoot
}

$env:PYTHONPATH = $ShadowRoot
Remove-Item Env:FRIDA_EXTENSION -ErrorAction SilentlyContinue

if ($args.Count -eq 0) {
    Write-Host "Usage: .\run-frida-patched.ps1 frida-ps -H 127.0.0.1:<port>"
    exit 1
}

& $args[0] @args[1..($args.Length - 1)]
