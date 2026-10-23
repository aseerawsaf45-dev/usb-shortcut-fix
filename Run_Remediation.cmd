@echo off
setlocal EnableExtensions
title USB Shortcut Fix - Master Launcher

echo ================================================================
echo             USB SHORTCUT VIRUS FIX & RECOVERY LAUNCHER
echo ================================================================
echo.
echo Please choose an execution mode:
echo.
echo   [1] Fast Remediation Mode (Classic Batch - Zero Dependencies)
echo   [2] Forensic & Advanced Mode (PowerShell - SHA256 & LNK Analysis)
echo   [3] Audit Only Mode (PowerShell - Read-Only Simulation / Dry Run)
echo   [4] Exit
echo.
set /p "CHOICE=Enter choice [1-4]: "

if "%CHOICE%"=="1" (
    start "" "%~dp0USB_Shortcut_Fix.bat"
    exit /b
)
if "%CHOICE%"=="2" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0USB-Shortcut-Fix.ps1\"\" -VerboseReport' -Verb RunAs"
    exit /b
)
if "%CHOICE%"=="3" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0USB-Shortcut-Fix.ps1\"\" -ScanOnly' -Verb RunAs"
    exit /b
)
exit /b
