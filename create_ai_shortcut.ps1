# NetGuard AI — AI Assistant Desktop Shortcut Creator
# Creates a shortcut on the Windows desktop that launches the AI window.

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$iconPath  = Join-Path $scriptDir "netguard_ai_icon.ico"
$batPath   = Join-Path $scriptDir "LANCER_NETGUARD_AI.bat"
$lnkPath   = Join-Path ([Environment]::GetFolderPath("Desktop")) "NetGuard AI.lnk"

if (-not (Test-Path $iconPath)) {
    Write-Host "[!] netguard_ai_icon.ico introuvable. Executez d'abord: python create_ai_icon.py" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $batPath)) {
    Write-Host "[!] LANCER_NETGUARD_AI.bat introuvable." -ForegroundColor Red
    exit 1
}

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($lnkPath)
$Shortcut.TargetPath       = $batPath
$Shortcut.WorkingDirectory = $scriptDir
$Shortcut.IconLocation     = "$iconPath,0"
$Shortcut.Description      = "NetGuard AI - AI Assistant (Claude API)"
$Shortcut.WindowStyle      = 7  # Minimized
$Shortcut.Save()

Write-Host "[OK] Raccourci cree: $lnkPath" -ForegroundColor Green
