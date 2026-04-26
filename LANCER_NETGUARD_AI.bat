@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Pro — AI Assistant

echo.
echo  +============================================+
echo  !      NetGuard Pro — AI Assistant           !
echo  !      Claude API + Capabilities             !
echo  +============================================+
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python n'est pas installe ou pas dans le PATH.
    echo     Telechargez Python: https://www.python.org/downloads/
    pause
    exit /b 1
)

if "%ANTHROPIC_API_KEY%"=="" (
    if not exist "%~dp0netguard_ai_settings.json" (
        echo [!] Aucune cle API detectee.
        echo     Option 1: set ANTHROPIC_API_KEY=sk-ant-...
        echo     Option 2: copie netguard_ai_settings.json.example vers netguard_ai_settings.json
        echo               et ajoute ta cle.
        echo.
    )
)

echo [*] Demarrage du serveur AI sur http://127.0.0.1:8770/ ...
cd /d "%~dp0"
python "%~dp0netguard_ai_server.py"

pause
