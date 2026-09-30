@echo off
rem Wrapper for start_sensor.ps1 -- a fresh Windows machine's default PowerShell
rem execution policy (Restricted / AllSigned) refuses to even LOAD an unsigned
rem .ps1 file, before the script's own internal "-ExecutionPolicy Bypass"
rem elevation relaunch ever gets a chance to run. -ExecutionPolicy Bypass here
rem covers that first hop; this .cmd itself needs no special permissions.
rem
rem   scripts\start_sensor.cmd            (port 8101)
rem   scripts\start_sensor.cmd 8100       (explicit port)
setlocal
set PORT=%1
if "%PORT%"=="" set PORT=8101
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_sensor.ps1" -Port %PORT%
