@echo off
title NetGuard AI — Desinstallation Service
echo.
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERREUR] Lance ce script en tant qu'Administrateur !
    pause
    exit /b 1
)

:: Arreter et supprimer la tache
schtasks /end /tn "NetGuardAI" >nul 2>&1
schtasks /delete /tn "NetGuardAI" /f >nul 2>&1

:: Tuer le processus Python si actif
taskkill /f /im python.exe /fi "WINDOWTITLE eq netguard*" >nul 2>&1

:: Supprimer le launcher VBS
if exist "%~dp0netguard_service.vbs" del "%~dp0netguard_service.vbs"

echo  [OK] Service NetGuard AI desinstalle.
echo  [OK] Il ne demarrera plus au boot.
echo.
pause
