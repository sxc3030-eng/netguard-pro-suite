@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite — Session Recorder
cd /d "%~dp0\recorder"
:: --headless: the bundled pywebview pointed at a WS-only port and crashed.
:: Headless = clean console-mode service. Other modules query it on ws://localhost:8860.
python recorder.py --headless
pause
