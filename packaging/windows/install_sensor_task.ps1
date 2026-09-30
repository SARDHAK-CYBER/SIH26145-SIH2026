<#
Installs the live sensor as an auto-starting, auto-restarting, ELEVATED background task (the Windows counterpart of a service).
Run ONCE from an elevated PowerShell:   powershell -ExecutionPolicy Bypass -File packaging\windows\install_sensor_task.ps1 -Port 8100

* runs as SYSTEM with highest privileges, so Npcap's "Administrators only" mode never raises a UAC prompt
* starts at boot; the task itself supervises the sensor and relaunches it 3 s after it exits for any reason; no execution time limit
* logs to <repo>\sensor-<port>.log ; remove with:  Unregister-ScheduledTask StealthTapSensor -Confirm:$false
Set STEALTHTAP_API_KEY (machine environment variable) before installing if the sensor binds beyond loopback.
#>
param([int]$Port = 8100, [string]$BindHost = "127.0.0.1")
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$py = Join-Path $repo "venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "venv not found at $py -- create it and pip install -r requirements.txt first" }
$log = "$repo\sensor-$Port.log"
# The loop lives INSIDE the task: Task Scheduler only restarts a task that exits with a failure, and a sensor that dies, is killed,
# or loses a port race can exit "cleanly" from the wrapper's point of view. Log is appended and truncated above 50 MB.
# Loads .env (same file docker-compose reads via ${VAR} interpolation) before the loop so this process shares
# STEALTHTAP_TOKEN_SECRET with the Docker `api` container -- without it, this sensor signs login tokens with its
# own random per-process secret, and a token from the dashboard's login (which always hits the API on :8000)
# fails verification here with a generic "session not accepted", even with the right password.
$envFile = "$repo\.env"
$loadEnv = "if (Test-Path '$envFile') { Get-Content '$envFile' | ForEach-Object { if (`$_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*`$' -and `$_ -notmatch '^\s*#') { [System.Environment]::SetEnvironmentVariable(`$Matches[1], `$Matches[2], 'Process') } } }"
$cmd = "`$env:SCAPY_USE_PCAPDNET='1'; Set-Location '$repo'; $loadEnv; while (`$true) { if ((Test-Path '$log') -and (Get-Item '$log').Length -gt 52428800) { Clear-Content '$log' }; & '$py' -m src.capture.live_agent serve --host $BindHost --port $Port *>> '$log'; Start-Sleep -Seconds 3 }"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$cmd`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "StealthTapSensor" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "StealthTapSensor"
Write-Host "StealthTapSensor installed and started on http://${BindHost}:$Port (log: $repo\sensor-$Port.log)"
