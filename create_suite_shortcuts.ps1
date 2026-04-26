# NetGuard Pro Suite - Recreate ALL desktop shortcuts with v3 distinct icons.
# Drops a fresh .lnk on the user desktop for each module that has a launcher.
# Run: powershell -ExecutionPolicy Bypass -File create_suite_shortcuts.ps1

$scriptDir     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$desktop       = [Environment]::GetFolderPath("Desktop")
$sentinelIcons = Join-Path $scriptDir "sentinel\icons"
$sentinelRoot  = Join-Path $scriptDir "sentinel"
$WshShell      = New-Object -ComObject WScript.Shell

# Generate icons if any are missing.
if (-not (Test-Path (Join-Path $scriptDir "netguard_icon.ico"))) {
    Write-Host "[..] Generation des icones du brand..." -ForegroundColor Yellow
    python (Join-Path $scriptDir "create_brand_icons.py")
}

$shortcuts = @(
    @{ Name="NetGuard Pro";              Bat="LANCER_NETGUARD.bat";    Icon="netguard_icon.ico";                     Desc="NetGuard Pro - Network Security Monitor v4.1" },
    @{ Name="NetGuard AI";               Bat="LANCER_NETGUARD_AI.bat"; Icon="netguard_ai_icon.ico";                  Desc="NetGuard Pro - AI Assistant (Claude API)" },
    @{ Name="MailShield Pro";            Bat="LANCER_MAILSHIELD.bat";  Icon="sentinel\icons\mailshield.ico";         Desc="Secure Email Client" },
    @{ Name="CleanGuard Pro";            Bat="LANCER_CLEANGUARD.bat";  Icon="sentinel\icons\cleanguard.ico";         Desc="System Cleaner & Malware Scanner" },
    @{ Name="SentinelOS";                Bat="LANCER_SENTINEL.bat";    Icon="sentinel\SentinelOS.ico";               Desc="Threat Intelligence & SOAR" },
    @{ Name="VPN Guard Pro";             Bat="LANCER_VPNGUARD.bat";    Icon="sentinel\icons\vpnguard.ico";           Desc="VPN Connection Manager" },
    @{ Name="Session Recorder";          Bat="LANCER_RECORDER.bat";    Icon="sentinel\icons\recorder.ico";           Desc="Session capture & evidence" },
    @{ Name="HoneyPot Agent";            Bat="LANCER_HONEYPOT.bat";    Icon="sentinel\icons\honeypot.ico";           Desc="Decoy & lure agent" },
    @{ Name="File Integrity Monitor";    Bat="LANCER_FIM.bat";         Icon="sentinel\icons\fim.ico";                Desc="Hash signature watch" },
    @{ Name="StrikeBack";                Bat="LANCER_STRIKEBACK.bat";  Icon="sentinel\icons\strikeback.ico";         Desc="RedTeam toolkit" }
)

$created = 0
$skipped = 0
foreach ($s in $shortcuts) {
    $batPath  = Join-Path $scriptDir $s.Bat
    $iconPath = Join-Path $scriptDir $s.Icon

    if (-not (Test-Path $batPath)) {
        Write-Host ("[skip] {0,-28} : {1} introuvable" -f $s.Name, $s.Bat) -ForegroundColor Yellow
        $skipped++
        continue
    }
    if (-not (Test-Path $iconPath)) {
        Write-Host ("[skip] {0,-28} : icon {1} introuvable" -f $s.Name, $s.Icon) -ForegroundColor Yellow
        $skipped++
        continue
    }

    $lnkPath = Join-Path $desktop ("{0}.lnk" -f $s.Name)
    $shortcut = $WshShell.CreateShortcut($lnkPath)
    $shortcut.TargetPath       = $batPath
    $shortcut.WorkingDirectory = $scriptDir
    $shortcut.IconLocation     = "$iconPath,0"
    $shortcut.Description      = $s.Desc
    $shortcut.WindowStyle      = 7  # Minimized
    $shortcut.Save()
    Write-Host ("[OK]   {0,-28} -> {1}" -f $s.Name, [IO.Path]::GetFileName($iconPath)) -ForegroundColor Green
    $created++
}

Write-Host ""
Write-Host ("=== {0} raccourcis crees / {1} ignores ===" -f $created, $skipped) -ForegroundColor Cyan
Write-Host ""
Write-Host "Si les icones ne s'affichent pas tout de suite, lance :" -ForegroundColor DarkCyan
Write-Host "  powershell -ExecutionPolicy Bypass -File force_icon_refresh.ps1" -ForegroundColor DarkCyan
