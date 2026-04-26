@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite - Session Recorder

:: Free port 8860 if a previous run left an orphan service.
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8860 " ^| findstr "LISTENING"') do (
    echo [*] Killing orphan PID %%a holding port 8860...
    taskkill /F /PID %%a >nul 2>&1
)

cd /d "%~dp0\recorder"
:: --headless: the bundled pywebview pointed at a WS-only port and crashed.
:: Headless = clean console-mode service queried over ws://localhost:8860.
python recorder.py --headless
pause
