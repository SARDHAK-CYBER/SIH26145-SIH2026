<#
Starts the StealthTap live sensor as a long-lived, ELEVATED process (one UAC approval).

Why elevated: with Npcap installed in "Administrators only" mode, every non-elevated process that opens the capture
driver makes Windows raise a UAC prompt (and wait ~2 minutes for it). One elevated sensor pays that once; the dashboard,
tests and tools then talk to it over HTTP and never open the driver themselves.

  powershell -File scripts\start_sensor.ps1            # port 8101, prompts once for elevation
  powershell -File scripts\start_sensor.ps1 -Port 8100
Logs: sensor-<port>.log next to this repo.
#>
param([int]$Port = 8101)

$repo = Split-Path -Parent $PSScriptRoot
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Port', $Port)
    Write-Host "Requested elevation -- approve the Windows prompt once. Sensor will listen on http://127.0.0.1:$Port"
    exit 0
}
Set-Location $repo
$env:SCAPY_USE_PCAPDNET = '1'

# Load .env into this process's environment -- same file docker-compose reads via ${VAR}
# interpolation. Without this, STEALTHTAP_TOKEN_SECRET is unset here, so this process
# signs login tokens with its own random per-process secret: a token from the Docker
# `api` container (port 8000) then fails verification against this sensor (port 8100)
# with a generic "session not accepted", even though the password was correct.
$envFile = Join-Path $repo ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$' -and $_ -notmatch '^\s*#') {
            [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
}

& "$repo\venv\Scripts\python.exe" -m src.capture.live_agent serve --port $Port *> "$repo\sensor-$Port.log"
