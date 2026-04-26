@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Suite - Session Recorder

cd /d "%~dp0\recorder"
python launch_recorder.py
pause
