@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite — File Integrity Monitor
cd /d "%~dp0\fim"
python file_integrity_monitor.py
pause
