@echo off
title NetGuard AI — Installation Service Windows
echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   NetGuard AI — Installation Service       ║
echo  ║   Demarrage automatique au boot Windows     ║
echo  ╚══════════════════════════════════════════════╝
echo.

:: Verifier les droits admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERREUR] Lance ce script en tant qu'Administrateur !
    pause
    exit /b 1
)

:: Trouver Python
for /f "tokens=*" %%i in ('where python 2^>nul') do set PYTHON_PATH=%%i
if "%PYTHON_PATH%"=="" (
    echo  [ERREUR] Python non trouve. Installe Python 3.10+ d'abord.
    pause
    exit /b 1
)
echo  [OK] Python trouve : %PYTHON_PATH%

:: Trouver le dossier du script
set SCRIPT_DIR=%~dp0
set SCRIPT_PATH=%SCRIPT_DIR%netguard.py
echo  [OK] Script : %SCRIPT_PATH%

:: Creer le script de lancement sans fenetre
set LAUNCHER=%SCRIPT_DIR%netguard_service.vbs
echo Set oShell = CreateObject("WScript.Shell") > "%LAUNCHER%"
echo oShell.Run "cmd /c cd /d ""%SCRIPT_DIR%"" && ""%PYTHON_PATH%"" netguard.py --no-block", 0, False >> "%LAUNCHER%"
echo  [OK] Launcher VBS cree : %LAUNCHER%

:: Verification du VBS genere
echo.
echo  [INFO] Contenu du VBS :
type "%LAUNCHER%"
echo.

:: Creer la tache planifiee
set TASK_NAME=NetGuardAI

:: Supprimer si existe deja
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

:: Creer la tache — demarrage au boot, en arriere-plan
schtasks /create ^
    /tn "%TASK_NAME%" ^
    /tr "wscript.exe \"%LAUNCHER%\"" ^
    /sc ONSTART ^
    /ru SYSTEM ^
    /rl HIGHEST ^
    /f ^
    /delay 0000:30
    
if %errorLevel% equ 0 (
    echo  [OK] Tache planifiee creee : %TASK_NAME%
) else (
    echo  [ERREUR] Echec creation tache planifiee
    pause
    exit /b 1
)

:: Demarrer maintenant
echo.
echo  Demarrage de NetGuard AI en arriere-plan...
schtasks /run /tn "%TASK_NAME%"
timeout /t 4 /nobreak >nul

:: Verification du demarrage
tasklist /fi "imagename eq python.exe" 2>nul | find /i "python" >nul
if %errorLevel% equ 0 (
    echo  [OK] NetGuard AI est en cours d'execution
) else (
    echo  [ATTENTION] Python ne semble pas actif. Verifiez le chemin Python.
)

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║  Installation reussie !                     ║
echo  ║                                             ║
echo  ║  NetGuard AI demarre automatiquement       ║
echo  ║  a chaque demarrage de Windows.             ║
echo  ║                                             ║
echo  ║  Dashboard : netguard_dashboard.html        ║
echo  ║  Port      : ws://localhost:8765            ║
echo  ╚══════════════════════════════════════════════╝
echo.
echo  Pour desinstaller : uninstall_service_windows.bat
echo.
pause
