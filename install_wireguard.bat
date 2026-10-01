@echo off
title NetGuard AI — Installation WireGuard VPN
echo.
echo  +================================================+
echo  ^|   NetGuard AI — Installation WireGuard VPN    ^|
echo  ^|   Tunnel VPN chiffre pour protection reseau    ^|
echo  +================================================+
echo.

:: Verifier les droits admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERREUR] Lance ce script en tant qu'Administrateur !
    echo           Clic droit ^> Executer en tant qu'administrateur
    pause
    exit /b 1
)

:: Verifier si WireGuard est deja installe
where wg >nul 2>&1
if %errorLevel% equ 0 (
    echo  [OK] WireGuard est deja installe :
    wg --version 2>nul || echo  Version non disponible
    echo.
    goto :check_path
)

:: Verifier si wireguard.exe existe dans Program Files
if exist "C:\Program Files\WireGuard\wg.exe" (
    echo  [OK] WireGuard trouve dans C:\Program Files\WireGuard
    goto :check_path
)

:: Installer via winget
echo  [INFO] Installation de WireGuard via winget...
echo.
winget install WireGuard.WireGuard --accept-package-agreements --accept-source-agreements --silent
if %errorLevel% neq 0 (
    echo.
    echo  [ERREUR] Echec installation via winget.
    echo  [INFO] Methode alternative :
    echo         1. Va sur https://www.wireguard.com/install/
    echo         2. Telecharge le MSI Windows
    echo         3. Installe manuellement
    echo         4. Relance ce script
    echo.
    pause
    exit /b 1
)

echo.
echo  [OK] WireGuard installe avec succes !

:check_path
:: Verifier/ajouter au PATH
echo.
echo  [INFO] Verification du PATH...
where wg >nul 2>&1
if %errorLevel% neq 0 (
    echo  [INFO] Ajout de WireGuard au PATH systeme...
    setx PATH "%PATH%;C:\Program Files\WireGuard" /M >nul 2>&1
    set "PATH=%PATH%;C:\Program Files\WireGuard"
    echo  [OK] PATH mis a jour
) else (
    echo  [OK] wg.exe est dans le PATH
)

:: Verification finale
echo.
echo  [INFO] Verification finale...
"C:\Program Files\WireGuard\wg.exe" --version 2>nul
if %errorLevel% neq 0 (
    wg --version 2>nul
)

:: Installer la dependance Python cryptography
echo.
echo  [INFO] Installation de la librairie Python cryptography...
pip install cryptography --quiet 2>nul
if %errorLevel% equ 0 (
    echo  [OK] cryptography installe
) else (
    echo  [ATTENTION] Echec installation cryptography (mode fallback disponible)
)

echo.
echo  +================================================+
echo  ^|  Installation WireGuard terminee !             ^|
echo  ^|                                                ^|
echo  ^|  Prochaine etape :                             ^|
echo  ^|    1. Lance NetGuard AI (netguard.py)         ^|
echo  ^|    2. Va dans l'onglet WireGuard               ^|
echo  ^|    3. Configure le endpoint (ton IP publique)  ^|
echo  ^|    4. Ajoute des peers                         ^|
echo  ^|    5. Demarre le VPN                           ^|
echo  ^|                                                ^|
echo  ^|  Ou lance : setup_wireguard.bat                ^|
echo  +================================================+
echo.
pause
