@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title SentinelOS v2.0 - Centre de Commandement

echo.
echo  ============================================
echo    SentinelOS v2.0
echo    Centre de Commandement Cybersecurite
echo  ============================================
echo.

:: -----------------------------------------------
:: ETAPE 1 : Verifier droits administrateur
:: -----------------------------------------------
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] Droits administrateur requis.
    echo  [*] Relancement en mode administrateur...
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b 0
)
echo  [OK] Droits administrateur confirmes.

:: -----------------------------------------------
:: ETAPE 2 : Verifier Python
:: -----------------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [!] Python n'est pas installe ou pas dans le PATH.
    echo      Telechargez Python: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)
echo  [OK] Python detecte.

:: -----------------------------------------------
:: ETAPE 3 : Verifier WireGuard (pour VPN Guard)
:: -----------------------------------------------
echo.
echo  [*] Verification de WireGuard...

where wg >nul 2>&1
if %errorLevel% equ 0 (
    echo  [OK] WireGuard est installe.
    goto :wg_ready
)

if exist "C:\Program Files\WireGuard\wg.exe" (
    echo  [OK] WireGuard trouve dans C:\Program Files\WireGuard
    goto :add_path
)

echo.
echo  [!] WireGuard n'est pas installe.
echo  [*] Installation automatique via winget...
echo.

winget install WireGuard.WireGuard --accept-package-agreements --accept-source-agreements --silent 2>nul
if %errorLevel% equ 0 (
    echo.
    echo  [OK] WireGuard installe avec succes !
    timeout /t 3 >nul
    goto :add_path
)

echo.
echo  [!] Installation automatique echouee.
echo  [*] Tentative de telechargement direct...
echo.

set "WG_INSTALLER=%TEMP%\wireguard-installer.exe"
powershell -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://download.wireguard.com/windows-client/wireguard-installer.exe' -OutFile '%WG_INSTALLER%' -UseBasicParsing } catch { exit 1 }" 2>nul
if exist "%WG_INSTALLER%" (
    echo  [*] Installateur telecharge, lancement...
    start /wait "" "%WG_INSTALLER%" /S
    timeout /t 3 >nul
    if exist "C:\Program Files\WireGuard\wg.exe" (
        echo  [OK] WireGuard installe !
        del "%WG_INSTALLER%" 2>nul
        goto :add_path
    )
    del "%WG_INSTALLER%" 2>nul
)

echo.
echo  [ATTENTION] WireGuard n'a pas pu etre installe automatiquement.
echo  [INFO] VPN Guard fonctionnera sans VPN. Installez WireGuard manuellement si besoin.
echo  [INFO] https://www.wireguard.com/install/
echo.

goto :wg_ready

:add_path
where wg >nul 2>&1
if %errorLevel% neq 0 (
    echo  [*] Ajout de WireGuard au PATH...
    setx PATH "%PATH%;C:\Program Files\WireGuard" /M >nul 2>&1
    set "PATH=%PATH%;C:\Program Files\WireGuard"
    echo  [OK] PATH mis a jour.
)

:wg_ready
echo  [OK] Verification WireGuard terminee.

:: -----------------------------------------------
:: ETAPE 4 : Installer TOUTES les dependances
:: -----------------------------------------------
echo.
echo  [*] Installation des dependances Python...
echo  [*] (websockets, pywebview, psutil, pystray, Pillow, cryptography, requests, scapy)
python -m pip install websockets pywebview psutil pystray Pillow cryptography requests scapy >nul 2>&1
echo  [OK] Dependances principales installees.
echo  [OK] Dependances Python installees.

:: -----------------------------------------------
:: ETAPE 5 : Lancer SentinelOS Cortex
:: -----------------------------------------------
echo.
echo  ============================================
echo    Tout est pret ! Lancement de SentinelOS...
echo  ============================================
echo.
echo  [*] Le Cortex va demarrer les 6 agents automatiquement :
echo      - NetGuard AI           (port 8765)
echo      - CleanGuard Pro         (port 8810)
echo      - MailShield Pro         (port 8801)
echo      - VPN Guard Pro          (port 8820)
echo      - HoneyPot Agent         (port 8830)
echo      - File Integrity Monitor (port 8840)
echo.
echo  [*] Dashboard unifie sur le port 8900
echo  [*] SentinelOS va se lancer dans la barre des taches.
echo  [*] Double-cliquez l'icone pour ouvrir le dashboard.
echo.

cd /d "%~dp0sentinel"
start /B pythonw "%~dp0sentinel\cortex.py" 2>nul
if %errorLevel% neq 0 (
    echo  [INFO] pythonw non disponible, lancement avec python...
    start /B python "%~dp0sentinel\cortex.py"
)

echo  [OK] SentinelOS demarre en arriere-plan !
echo  [*] Regardez l'icone dans la barre des taches (pres de l'horloge).
echo.
timeout /t 5 >nul
