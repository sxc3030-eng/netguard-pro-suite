@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite - HoneyPot Agent

:: Free common honeypot ports if a previous run left orphans.
for %%P in (8870 2222 8080) do (
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":%%P " ^| findstr "LISTENING"') do (
        echo [*] Killing orphan PID %%a holding port %%P...
        taskkill /F /PID %%a >nul 2>&1
    )
)

cd /d "%~dp0\honeypot"
python honeypot.py
pause
