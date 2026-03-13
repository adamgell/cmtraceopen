@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "LAUNCH_SCRIPT=%SCRIPT_DIR%scripts\Launch-CMTraceOpen.ps1"

if not exist "%LAUNCH_SCRIPT%" (
    echo Launcher script not found: "%LAUNCH_SCRIPT%"
    exit /b 1
)

where pwsh.exe >nul 2>nul
if errorlevel 1 (
    set "POWERSHELL_EXE=powershell.exe"
) else (
    set "POWERSHELL_EXE=pwsh.exe"
)

start "CMTrace Open Dev Shell" "%POWERSHELL_EXE%" -NoLogo -NoExit -ExecutionPolicy Bypass -File "%LAUNCH_SCRIPT%" %*
