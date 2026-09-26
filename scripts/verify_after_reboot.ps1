<#
Run this after rebooting the machine (elevated PowerShell is best, but not required) to confirm the deployment came back on its own:
    powershell -ExecutionPolicy Bypass -File scripts\verify_after_reboot.ps1 [-SensorPort 8100]

Checks: machine uptime (proves you rebooted), the sensor answers on its port and runs as SYSTEM (elevated shell only), the sensor can
capture, Docker services are up and healthy, and TLS answers on 443/8443. Exit code 0 = everything came back without a manual step.
#>
param([int]$SensorPort = 8100)
$ok = $true
function Check($name, $pass, $detail) { if ($pass) { "[ ok ] $name  $detail" } else { "[FAIL] $name  $detail"; $script:ok = $false } }

$up = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Check "uptime" ($up.TotalMinutes -lt 60) ("{0:N0} min since boot (run this within an hour of rebooting)" -f $up.TotalMinutes)

try { $h = Invoke-WebRequest "http://127.0.0.1:$SensorPort/health" -UseBasicParsing -TimeoutSec 5; Check "sensor answers" ($h.StatusCode -eq 200) "port $SensorPort" } catch { Check "sensor answers" $false "port $SensorPort not reachable" }
$pid8 = (Get-NetTCPConnection -LocalPort $SensorPort -State Listen -ErrorAction SilentlyContinue | Select -First 1).OwningProcess
if ($pid8) {
  $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$pid8" | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue)
  if ($owner -and $owner.User) { Check "sensor runs as SYSTEM (task, not a user session)" ($owner.User -eq "SYSTEM") "owner $($owner.Domain)\$($owner.User)" }
  else { "[ -- ] sensor owner not readable from a non-elevated shell (rerun elevated to see it)" }
}
try {
  Invoke-RestMethod -Method Post "http://127.0.0.1:$SensorPort/capture/start" -ContentType "application/json" -Body '{"interface":"Wi-Fi","bpf":"ip or ip6"}' -TimeoutSec 20 | Out-Null
  Start-Sleep 6
  $st = Invoke-RestMethod "http://127.0.0.1:$SensorPort/capture/status" -TimeoutSec 10
  Check "sensor captures without a prompt" ($st.capture.recv -gt 0) "$($st.capture.recv) packets, kernel drops $($st.capture.kernel_drop)"
  Invoke-RestMethod -Method Post "http://127.0.0.1:$SensorPort/capture/stop" -TimeoutSec 10 | Out-Null
} catch { Check "sensor captures without a prompt" $false $_.Exception.Message }

$env:Path += ";C:\Program Files\Docker\Docker\resources\bin"
try {
  $ps = docker compose ps --format json 2>$null | ForEach-Object { $_ | ConvertFrom-Json }
  $running = @($ps | Where-Object { $_.State -eq "running" }).Count
  Check "docker services running" ($running -ge 10) "$running running"
  $bad = @($ps | Where-Object { $_.Health -eq "unhealthy" })
  Check "no unhealthy service" ($bad.Count -eq 0) (($bad | % { $_.Service }) -join ",")
} catch { Check "docker services running" $false "docker not reachable (is Docker Desktop set to start at login?)" }
foreach ($u in @("https://localhost/", "https://localhost:8443/health")) {
  try { $c = & curl.exe -sk -o NUL -w "%{http_code}" --max-time 10 $u; Check "TLS $u" ($c -eq "200") "HTTP $c" } catch { Check "TLS $u" $false "no answer" }
}
if ($ok) { "`nALL GOOD: the deployment recovered from the reboot on its own."; exit 0 } else { "`nSomething did not come back -- see [FAIL] lines."; exit 1 }
