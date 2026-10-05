<#
.SYNOPSIS
  Construit NetGuard AI pour Windows : dossier exécutable (PyInstaller) puis installateur (Inno Setup).

.DESCRIPTION
  - PyInstaller --onedir : dist\NetGuardAI\NetGuardAI.exe + ses fichiers.
  - Aucun pilote ni scapy : le moteur de capture est ETW (intégré à Windows).
  - L'exécutable demande l'élévation (manifeste UAC) : ETW et le pare-feu en ont besoin.
    -NoUac construit une variante sans élévation, pour les tests automatiques.
  - Les données de l'utilisateur vont dans %LOCALAPPDATA%\NetGuard AI (netguard_paths.py).
  - Inno Setup (ISCC.exe) produit dist\NetGuardAI-Setup-<version>.exe.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File packaging\build_exe.ps1
  powershell -ExecutionPolicy Bypass -File packaging\build_exe.ps1 -NoUac -SkipInstaller
#>
param(
  [string]$Version = "4.2.1",
  [switch]$NoUac,
  [switch]$SkipInstaller,
  [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$name = "NetGuardAI"
$distDir = Join-Path $root "dist"
$workDir = Join-Path $root "build\pyinstaller"

$pyArgs = @(
  "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--windowed",
  "--name", $name,
  "--icon", "$root\netguard_icon.ico",
  "--distpath", $distDir, "--workpath", $workDir, "--specpath", $workDir,
  "--add-data", "$root\netguard_dashboard.html;.",
  "--add-data", "$root\netguard_map.html;.",
  "--add-data", "$root\netguard_network.html;.",
  "--add-data", "$root\netguard_panels.html;.",
  "--add-data", "$root\netguard_history.html;.",
  "--add-data", "$root\netguard_analyze.html;.",
  "--add-data", "$root\netguard_help.html;.",
  "--add-data", "$root\netguard_service.html;.",
  "--add-data", "$root\netguard_ai.html;.",
  "--add-data", "$root\netguard_ai_icon.png;.",
  "--add-data", "$root\netguard_icon.ico;.",
  "--add-data", "$root\netguard_settings.json.example;.",
  "--add-data", "$root\LICENSE;.",
  "--add-data", "$root\THIRD_PARTY_LICENSES.md;.",
  "--add-data", "$root\PRIVACY_POLICY_NETGUARD_AI.md;.",
  "--hidden-import", "netguard_ai_server",
  "--hidden-import", "netguard_paths",
  "--hidden-import", "license_manager",
  "--hidden-import", "startup_utils",
  "--hidden-import", "config",
  "--hidden-import", "capture.etw_engine",
  "--hidden-import", "capture.poll_engine",
  "--hidden-import", "websockets.asyncio.server",
  "--hidden-import", "websockets.asyncio.client",
  "--exclude-module", "scapy",
  "--exclude-module", "PyQt6",
  "--exclude-module", "PyQt5",
  "--exclude-module", "tkinter",
  "--exclude-module", "pytest"
)
if (-not $NoUac) { $pyArgs += "--uac-admin" }
$pyArgs += "netguard.py"

Write-Host "[1/2] PyInstaller ($name, UAC admin: $(-not $NoUac))"
& $Python @pyArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller a échoué (code $LASTEXITCODE)" }
$exe = Join-Path $distDir "$name\$name.exe"
if (-not (Test-Path $exe)) { throw "exécutable introuvable: $exe" }
Write-Host "    -> $exe"

if ($SkipInstaller) { Write-Host "Installateur ignoré (-SkipInstaller)"; exit 0 }

Write-Host "[2/2] Inno Setup"
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 introuvable (https://jrsoftware.org/isdl.php)" }
& $iscc "/DAppVersion=$Version" "/DSourceDir=$distDir\$name" "/DOutputDir=$distDir" (Join-Path $root "packaging\NetGuardAI.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup a échoué (code $LASTEXITCODE)" }
$setup = Join-Path $distDir "NetGuardAI-Setup-$Version.exe"
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash
Write-Host "OK -> $setup"
Write-Host "SHA-256 $hash"
