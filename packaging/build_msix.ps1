<#
.SYNOPSIS
  Construit le paquet MSIX « NetGuard AI » pour le Microsoft Store.

.DESCRIPTION
  1. PyInstaller --onedir (pas --onefile : un MSIX est déjà un conteneur, et
     --onefile extrait dans %TEMP% à chaque lancement).
  2. Copie des ressources (HTML, icônes, exemple de réglages) dans le dossier
     du paquet ; AUCUN fichier de données réel (settings, licence, captures).
  3. makeappx pack + signtool (certificat Partner Center ou cert de test).

  Prérequis : Windows 10 SDK (makeappx.exe, signtool.exe), Python + requirements.txt,
  PyInstaller. Variables à ajuster : $PublisherCN, $PfxPath.

  Les données écrites par l'application vont dans %LOCALAPPDATA%\NetGuard AI
  (netguard_paths.py détecte le dossier WindowsApps en lecture seule).
#>
param(
  [string]$PublisherCN = "CN=PUBLISHER_CN",
  [string]$PackageName = "NETGUARD_PACKAGE_NAME",
  [string]$Version = "4.2.2.0",
  [string]$PfxPath = "",
  [string]$PfxPassword = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

Write-Host "[1/4] PyInstaller (onedir)"
python -m PyInstaller --noconfirm --clean --onedir --windowed --name NetGuardAI `
  --icon netguard_icon.ico `
  --add-data "netguard_dashboard.html;." --add-data "netguard_map.html;." `
  --add-data "netguard_network.html;." --add-data "netguard_panels.html;." `
  --add-data "netguard_history.html;." --add-data "netguard_analyze.html;." `
  --add-data "netguard_help.html;." --add-data "netguard_service.html;." `
  --add-data "netguard_ai.html;." --add-data "netguard_ai_icon.png;." `
  --add-data "netguard_icon.png;." --add-data "netguard_settings.json.example;." `
  --add-data "sentinel\sentinel_map.html;sentinel" `
  --hidden-import netguard_ai_server --hidden-import netguard_paths --hidden-import license_manager `
  netguard.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller a échoué" }

$pkg = Join-Path $root "dist\msix"
if (Test-Path $pkg) { Remove-Item -Recurse -Force $pkg }
New-Item -ItemType Directory -Force $pkg | Out-Null
Copy-Item -Recurse (Join-Path $root "dist\NetGuardAI\*") $pkg

Write-Host "[2/4] Manifeste + assets"
$manifest = Get-Content (Join-Path $root "packaging\msix\AppxManifest.xml") -Raw
$manifest = $manifest.Replace("CN=PUBLISHER_CN", $PublisherCN).Replace("NETGUARD_PACKAGE_NAME", $PackageName).Replace('Version="4.2.2.0"', "Version=`"$Version`"")
Set-Content -Path (Join-Path $pkg "AppxManifest.xml") -Value $manifest -Encoding utf8
New-Item -ItemType Directory -Force (Join-Path $pkg "Assets") | Out-Null
# Logos : générer depuis netguard_logo.svg (150x150, 44x44, 310x150, 50x50 StoreLogo)
Copy-Item (Join-Path $root "netguard_icon.png") (Join-Path $pkg "Assets\Square150x150Logo.png") -ErrorAction SilentlyContinue
Copy-Item (Join-Path $root "netguard_icon.png") (Join-Path $pkg "Assets\Square44x44Logo.png") -ErrorAction SilentlyContinue
Copy-Item (Join-Path $root "netguard_icon.png") (Join-Path $pkg "Assets\Wide310x150Logo.png") -ErrorAction SilentlyContinue
Copy-Item (Join-Path $root "netguard_icon.png") (Join-Path $pkg "Assets\StoreLogo.png") -ErrorAction SilentlyContinue

Write-Host "[3/4] makeappx pack"
$out = Join-Path $root "dist\NetGuardAI_$Version.msix"
if (Test-Path $out) { Remove-Item -Force $out }
makeappx pack /d $pkg /p $out /o
if ($LASTEXITCODE -ne 0) { throw "makeappx a échoué" }

Write-Host "[4/4] Signature"
if ($PfxPath) {
  signtool sign /fd SHA256 /a /f $PfxPath /p $PfxPassword $out
  if ($LASTEXITCODE -ne 0) { throw "signtool a échoué" }
} else {
  Write-Warning "Pas de certificat : paquet non signé (le Store signe lui-même les soumissions .msixupload)."
}
Write-Host "OK -> $out"
