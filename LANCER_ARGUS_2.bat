@echo off
REM Argus 2.0 — Cybersecurity Workbench (PyQt6 + QtWebEngine)
REM Sandbox-first browser with Claude arbitrage + surveillance built-in
REM Sister product to Mythos (Greek mythology naming)
REM
REM NOTE: NetGuard backend is NOT auto-started anymore. Argus runs
REM standalone — the live feed will simply be empty until the user
REM explicitly launches NetGuard via the 🛡 button in dock row 3.
REM This avoids the netguard.py "enter your key" prompt firing every
REM launch, which was friction for users who only want the browser.

cd /d "%~dp0"
title Argus — Cybersecurity Workbench

REM Launch Argus via pythonw (no console window — Python's QIcon takes over
REM in the taskbar). Errors written to argus_data\launch_error.log.
if not exist "argus_data" mkdir argus_data
start "" pythonw argus_pyqt.py 2>argus_data\launch_error.log
