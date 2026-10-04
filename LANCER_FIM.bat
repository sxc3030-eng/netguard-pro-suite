@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite - File Integrity Monitor

:: Free port 8840 if a previous run left an orphan service.
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8840 " ^| findstr "LISTENING"') do (
    echo [*] Killing orphan PID %%a holding port 8840...
    taskkill /F /PID %%a >nul 2>&1
)

cd /d "%~dp0\fim"
python file_integrity_monitor.py
pause
