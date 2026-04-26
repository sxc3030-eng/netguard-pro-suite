# NetGuard Pro Suite — Create Desktop Shortcuts for ALL modules
# Run: powershell -ExecutionPolicy Bypass -File create_all_shortcuts.ps1

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$desktop   = [Environment]::GetFolderPath("Desktop")
$iconPath  = Join-Path $scriptDir "netguard_icon.ico"
$WshShell  = New-Object -ComObject WScript.Shell

# Generate icons if missing (uses unified brand generator)
if (-not (Test-Path $iconPath)) {
    Write-Host "[..] Generation des icones de la suite..." -ForegroundColor Yellow
    $brand = Join-Path $scriptDir "create_brand_icons.py"
    if (Test-Path $brand) {
        python $brand
    } else {
        python (Join-Path $scriptDir "create_icon.py")
    }
}

$shortcuts = @(
    @{ Name="NetGuard Pro";       Bat="LANCER_NETGUARD.bat";    Desc="Network Security Monitor v3.0" },
    @{ Name="MailShield Pro";     Bat="LANCER_MAILSHIELD.bat";  Desc="Secure Email Client v2.0" },
    @{ Name="CleanGuard";        Bat="LANCER_CLEANGUARD.bat";  Desc="System Cleaner & Malware Scanner" },
    @{ Name="Sentinel OS";       Bat="LANCER_SENTINEL.bat";    Desc="Threat Intelligence & SOAR" },
    @{ Name="VPNGuard";          Bat="LANCER_VPNGUARD.bat";    Desc="VPN Connection Manager" }
)

$created = 0
foreach ($s in $shortcuts) {
    $batPath = Join-Path $scriptDir $s.Bat
    if (-not (Test-Path $batPath)) {
        Write-Host "[SKIP] $($s.Name) - $($s.Bat) introuvable" -ForegroundColor Yellow
        continue
    }
    $lnkPath = Join-Path $desktop "$($s.Name).lnk"
    $Shortcut = $WshShell.CreateShortcut($lnkPath)
    $Shortcut.TargetPath       = $batPath
    $Shortcut.WorkingDirectory = $scriptDir
    if (Test-Path $iconPath) {
        $Shortcut.IconLocation = "$iconPath,0"
    }
    $Shortcut.Description  = $s.Desc
    $Shortcut.WindowStyle  = 7  # Minimized
    $Shortcut.Save()
    Write-Host "[OK] $($s.Name) -> $lnkPath" -ForegroundColor Green
    $created++
}

Write-Host ""
Write-Host "=== $created raccourcis crees sur le Bureau ===" -ForegroundColor Cyan
