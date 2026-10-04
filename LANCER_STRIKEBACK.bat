@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite - StrikeBack / RedTeam Toolkit

:: Free port 8880 if a previous run left an orphan service.
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8880 " ^| findstr "LISTENING"') do (
    echo [*] Killing orphan PID %%a holding port 8880...
    taskkill /F /PID %%a >nul 2>&1
)

cd /d "%~dp0\strikeback"
python strikeback.py --headless
pause
