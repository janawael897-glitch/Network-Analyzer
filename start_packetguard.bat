@echo off
title PacketGuard - Starting...

REM Re-launch as Administrator if not already elevated
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

color 0A
echo.
echo  =============================================
echo   PacketGuard  ^|  Startup
echo  =============================================
echo.

start "PacketGuard" cmd /k "cd /d "%~dp0code" && python app.py"

echo  PacketGuard starting...
echo  Open browser at: http://localhost:5000
echo.
pause
