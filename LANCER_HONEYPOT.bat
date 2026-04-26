@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite — HoneyPot Agent
cd /d "%~dp0\honeypot"
python honeypot.py
pause
