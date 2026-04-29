@echo off
REM NetGuard Pro — Mode Fantôme (auto-elevation pour Npcap admin-only)
REM Lance le tray invisible. Le tray spawn netguard.py backend automatiquement.

REM Auto-elevation
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b 0
)

cd /d "%~dp0"
chcp 65001 >nul 2>&1
set PYTHONUTF8=1

REM Lance le tray en pythonw (pas de console). Le tray lui-même spawn netguard.py.
start "" pythonw netguard_tray.py

exit /b 0
