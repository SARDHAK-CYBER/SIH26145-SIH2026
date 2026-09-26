<#
Installs the live sensor as an auto-starting, auto-restarting, ELEVATED background task (the Windows counterpart of a service).
Run ONCE from an elevated PowerShell:   powershell -ExecutionPolicy Bypass -File packaging\windows\install_sensor_task.ps1 -Port 8100

* runs as SYSTEM with highest privileges, so Npcap's "Administrators only" mode never raises a UAC prompt
* starts at boot, restarts within 1 minute if the process dies (up to 999 times), no execution time limit
* logs to <repo>\sensor-<port>.log ; remove with:  Unregister-ScheduledTask StealthTapSensor -Confirm:$false
Set STEALTHTAP_API_KEY (machine environment variable) before installing if the sensor binds beyond loopback.
#>
param([int]$Port = 8100, [string]$BindHost = "127.0.0.1")
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$py = Join-Path $repo "venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "venv not found at $py -- create it and pip install -r requirements.txt first" }
$cmd = "`$env:SCAPY_USE_PCAPDNET='1'; Set-Location '$repo'; & '$py' -m src.capture.live_agent serve --host $BindHost --port $Port *> '$repo\sensor-$Port.log'"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$cmd`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "StealthTapSensor" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "StealthTapSensor"
Write-Host "StealthTapSensor installed and started on http://${BindHost}:$Port (log: $repo\sensor-$Port.log)"
