@echo off
title NetGuard AI — Build Windows .exe
color 0B

echo.
echo ==========================================
echo   NetGuard AI — Build Installateur
echo ==========================================
echo.

:: Vérifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python non trouvé. Installe Python 3.10+ depuis python.org
    pause & exit /b 1
)

:: Installer PyInstaller si absent
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installation de PyInstaller...
    pip install pyinstaller --quiet
)

:: Installer les dépendances
echo [INFO] Installation des dependances...
pip install websockets scapy requests --quiet

:: Créer le dossier de build
if not exist "dist" mkdir dist
if not exist "build_temp" mkdir build_temp

:: Copier les fichiers HTML dans un dossier
echo [INFO] Copie des fichiers HTML...
if not exist "build_temp\html" mkdir build_temp\html
copy *.html build_temp\html\ >nul 2>&1

:: Build avec PyInstaller
echo [INFO] Compilation en cours...
pyinstaller ^
    --onefile ^
    --noconsole ^
    --name "NetGuardAI" ^
    --icon "netguard_icon.ico" ^
    --add-data "*.html;." ^
    --add-data "netguard_settings.json;." ^
    --hidden-import websockets ^
    --hidden-import websockets.legacy ^
    --hidden-import websockets.legacy.server ^
    --hidden-import scapy ^
    --hidden-import scapy.all ^
    --hidden-import asyncio ^
    --hidden-import json ^
    --hidden-import hashlib ^
    --hidden-import secrets ^
    --distpath dist ^
    --workpath build_temp ^
    --specpath build_temp ^
    netguard.py

if errorlevel 1 (
    echo.
    echo [ERREUR] Build échoué. Voir les erreurs ci-dessus.
    pause & exit /b 1
)

echo.
echo ==========================================
echo   Build réussi!
echo   Fichier: dist\NetGuardAI.exe
echo ==========================================
echo.

:: Nettoyer les fichiers temporaires
rmdir /s /q build_temp >nul 2>&1

echo [INFO] Nettoyage terminé.
echo.
echo Pour créer l'installateur complet, installe NSIS:
echo https://nsis.sourceforge.io/Download
echo Puis lance: build_installer.bat
echo.
pause
