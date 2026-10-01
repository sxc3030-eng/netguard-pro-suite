@echo off
REM NetGuard launcher with auto-elevation to Administrator.
REM Required when Npcap is in "Admin-only mode" — otherwise scapy capture
REM triggers UAC popups every 2 seconds in a loop.

REM ── Self-elevation check ──────────────────────────────────────
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Non-admin shell detected. Requesting elevation...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b 0
)

REM ── Now running as Administrator ─────────────────────────────
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard AI (Admin) — sniffer + AI

echo.
echo  +============================================+
echo  !  NetGuard AI — ADMIN MODE                 !
echo  !  Sniffer scapy + Claude AI assistant       !
echo  +============================================+
echo.

cd /d "%~dp0"

REM Start NetGuard sniffer in background
start "NetGuard Sniffer" /B pythonw netguard.py
timeout /t 2 /nobreak >NUL

REM Start AI server in foreground (so terminal shows its logs)
echo [*] Sniffer demarre. Lancement du serveur AI...
echo.
python netguard_ai_server.py

pause
