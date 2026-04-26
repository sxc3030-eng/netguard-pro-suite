@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite — StrikeBack / RedTeam Toolkit
cd /d "%~dp0\strikeback"
python strikeback.py
pause
