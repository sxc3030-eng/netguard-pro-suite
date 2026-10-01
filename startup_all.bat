@echo off
:: NetGuard AI Suite - Dual Startup (all modules)
:: Launches NetGuard + all sub-modules at Windows boot
cd /d "%~dp0"

echo.
echo  ============================================
echo    NetGuard AI Suite v3.0.0 - Demarrage
echo  ============================================
echo.

:: 1. NetGuard AI (main backend + dashboard)
echo [1/5] Demarrage NetGuard AI...
start "" /min pythonw netguard.py

:: 2. MailShield Pro
if exist "mailshield\mailshield.py" (
    echo [2/5] Demarrage MailShield Pro...
    start "" /min pythonw mailshield\mailshield.py
) else (
    echo [2/5] MailShield - SKIP (non trouve)
)

:: 3. CleanGuard
if exist "cleanguard\cleanguard.py" (
    echo [3/5] Demarrage CleanGuard...
    start "" /min pythonw cleanguard\cleanguard.py
) else (
    echo [3/5] CleanGuard - SKIP (non trouve)
)

:: 4. Sentinel OS
if exist "sentinel\cortex.py" (
    echo [4/5] Demarrage Sentinel OS...
    start "" /min pythonw sentinel\cortex.py
) else (
    echo [4/5] Sentinel - SKIP (non trouve)
)

:: 5. VPNGuard
if exist "vpnguard\vpnguard.py" (
    echo [5/5] Demarrage VPNGuard...
    start "" /min pythonw vpnguard\vpnguard.py
) else (
    echo [5/5] VPNGuard - SKIP (non trouve)
)

echo.
echo  [OK] Tous les modules sont lances.
echo  Dashboard : netguard_dashboard.html
echo.
timeout /t 3
exit
