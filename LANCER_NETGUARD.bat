@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard AI v4.1.0

echo.
echo  +============================================+
echo  !      NetGuard AI v4.1.0                   !
echo  !      Surveillance Reseau                   !
echo  +============================================+
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python n'est pas installe ou pas dans le PATH.
    echo     Telechargez Python: https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Install dependencies
echo [*] Verification des dependances...
python -m pip install scapy websockets pywebview pystray Pillow >nul 2>&1

:: Launch NetGuard (pywebview opens its own window, no browser needed)
echo [*] Demarrage de NetGuard AI...
cd /d "%~dp0"
python "%~dp0netguard.py"

pause
