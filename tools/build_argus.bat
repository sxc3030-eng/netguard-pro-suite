@echo off
REM ============================================================================
REM Argus build script — Windows
REM ============================================================================
REM
REM Requires:  pip install pyinstaller (already in requirements-dev.txt)
REM Optional:  signtool.exe in PATH (install via Windows SDK) for code signing
REM
REM Usage:
REM     tools\build_argus.bat
REM
REM Output:
REM     build\dist\Argus\Argus.exe          (one-folder bundle)
REM     build\dist\Argus-portable.zip       (portable zip of the same)
REM
REM Code signing is intentionally separate — see docs/AUTHENTICODE.md.
REM ============================================================================

setlocal ENABLEEXTENSIONS

REM --- Resolve repo root: this script lives in <repo>\tools\ ------------------
cd /d "%~dp0\.."

echo.
echo === Argus build — one-folder bundle ===
echo Repo root: %CD%
echo.

REM --- Sanity: PyInstaller present? ------------------------------------------
REM We invoke via `python -m PyInstaller` rather than the bare `pyinstaller`
REM CLI: the Windows Store / per-user Python installs frequently leave the
REM `Scripts\` dir off PATH, which would break the bat for no good reason.
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PyInstaller not installed in the current Python.
    echo         Install with:  python -m pip install pyinstaller
    exit /b 1
)

REM --- Clean previous build artefacts ----------------------------------------
if exist "build\build" (
    echo [INFO] Removing build\build ...
    rmdir /s /q "build\build"
)
if exist "build\dist" (
    echo [INFO] Removing build\dist ...
    rmdir /s /q "build\dist"
)

REM --- Run PyInstaller --------------------------------------------------------
echo [INFO] Running PyInstaller ...
python -m PyInstaller --clean --noconfirm ^
    --workpath build\build ^
    --distpath build\dist ^
    build\Argus.spec
if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller build failed. Scroll up for details.
    exit /b 1
)

REM --- Copy top-level docs into the dist folder -------------------------------
REM (The spec already bundles these via `datas`, but copying again here makes
REM  the dist tree obvious to a non-developer browsing it.)
if exist "README.md"   copy /Y "README.md"   "build\dist\Argus\" >nul
if exist "LICENSE"     copy /Y "LICENSE"     "build\dist\Argus\" >nul
if exist "SECURITY.md" copy /Y "SECURITY.md" "build\dist\Argus\" >nul

REM --- Create a portable zip --------------------------------------------------
echo [INFO] Creating portable zip ...
powershell -NoProfile -Command "Compress-Archive -Path 'build\dist\Argus\*' -DestinationPath 'build\dist\Argus-portable.zip' -Force"
if errorlevel 1 (
    echo [WARN] Failed to create portable zip. The folder bundle is still usable.
)

echo.
echo ============================================================================
echo  Build complete.
echo  Bundle folder : build\dist\Argus\Argus.exe
echo  Portable zip  : build\dist\Argus-portable.zip
echo ============================================================================
echo.
echo Optional next step — sign the binary (one of):
echo.
echo   Trusted Signing (recommended, see docs/AUTHENTICODE.md):
echo     signtool sign /a /tr http://timestamp.acs.microsoft.com /td sha256 /fd sha256 build\dist\Argus\Argus.exe
echo.
echo   Sectigo / DigiCert OV cert on a USB token:
echo     signtool sign /a /n "Your Legal Name" /tr http://timestamp.sectigo.com /td sha256 /fd sha256 build\dist\Argus\Argus.exe
echo.

endlocal
exit /b 0
