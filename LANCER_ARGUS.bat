@echo off
REM Argus — NetGuard Cybersecurity Workbench
REM Single-window pywebview shell wrapping the entire NetGuard Suite.
REM Auth invisible, no Edge tracking-prevention issues.

cd /d "%~dp0"
title Argus

REM Ensure NetGuard is running so Argus can talk to ws://localhost:8765
tasklist /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq NetGuard*" 2>NUL | find /I "python.exe" >NUL
if errorlevel 1 (
    echo NetGuard not detected — starting it in background first...
    start "" /B pythonw netguard.py
    echo Waiting 3s for NetGuard to bind WebSocket...
    timeout /t 3 /nobreak >NUL
)

REM Ensure AI server is running (optional but recommended for the AI tab)
tasklist /FI "IMAGENAME eq python3.13.exe" 2>NUL | findstr /C:"netguard_ai_server.py" >NUL
if errorlevel 1 (
    start "" /B pythonw netguard_ai_server.py --no-browser
    timeout /t 1 /nobreak >NUL
)

REM Launch Argus
python argus.py
