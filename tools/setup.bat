@echo off
REM svs-autologin setup wrapper: relaunches install.ps1 elevated.
REM (Right-click Run-as-admin on a .bat is muscle memory; .ps1 is not.)
REM ASCII only - console codepage on other machines is a roulette (risk #8).

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
echo.
pause
