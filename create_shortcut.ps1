# NetGuard AI — Desktop Shortcut Creator
# Creates a shortcut on the Windows desktop with the NetGuard icon

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$iconPath  = Join-Path $scriptDir "netguard_icon.ico"
$batPath   = Join-Path $scriptDir "LANCER_NETGUARD.bat"
$lnkPath   = Join-Path ([Environment]::GetFolderPath("Desktop")) "NetGuard AI.lnk"

if (-not (Test-Path $iconPath)) {
    Write-Host "[!] netguard_icon.ico introuvable. Executez d'abord: python create_icon.py" -ForegroundColor Red
    exit 1
}

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($lnkPath)
$Shortcut.TargetPath       = $batPath
$Shortcut.WorkingDirectory = $scriptDir
$Shortcut.IconLocation     = "$iconPath,0"
$Shortcut.Description      = "NetGuard AI v3.0 - Network Security Monitor"
$Shortcut.WindowStyle      = 7  # Minimized
$Shortcut.Save()

Write-Host "[OK] Raccourci cree: $lnkPath" -ForegroundColor Green
