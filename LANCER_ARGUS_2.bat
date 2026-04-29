@echo off
REM Argus 2.0 — Real PyQt6 + QtWebEngine browser shell
REM Layout : transparent live feed top, Chromium middle, 3-row dock bottom
REM         floating tabs + mode badge + F12 dev tools

cd /d "%~dp0"
title Argus 2.0

REM Ensure NetGuard is running (background) so live feed has data + Argus can talk to ws://localhost:8765
tasklist /FI "IMAGENAME eq python.exe" 2>NUL | findstr /C:"python.exe" >NUL
if errorlevel 1 (
    echo NetGuard not detected — starting it in background...
    start "" /B pythonw netguard.py
    timeout /t 2 /nobreak >NUL
)

REM Launch Argus 2.0
python argus_pyqt.py
