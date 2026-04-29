@echo off
REM Argus 2.0 — Cybersecurity Workbench (PyQt6 + QtWebEngine)
REM Sandbox-first browser with Claude arbitrage + surveillance built-in
REM Sister product to Mythos (Greek mythology naming)

cd /d "%~dp0"
title Argus — Cybersecurity Workbench

REM Ensure NetGuard backend is running (background) so live feed has data
REM and Argus can reach the AI server at localhost:8770.
tasklist /FI "IMAGENAME eq python.exe" 2>NUL | findstr /C:"python.exe" >NUL
if errorlevel 1 (
    echo NetGuard backend not detected — starting it in background...
    start "" /B pythonw netguard.py
    timeout /t 2 /nobreak >NUL
)

REM Launch Argus via pythonw (no console window — Python's QIcon takes over
REM in the taskbar). Errors written to argus_data\launch_error.log.
if not exist "argus_data" mkdir argus_data
start "" pythonw argus_pyqt.py 2>argus_data\launch_error.log
