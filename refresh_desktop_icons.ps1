# NetGuard Pro Suite — Refresh icons on ALL existing desktop shortcuts.
# Matches by .lnk file name (module keyword), updates IconLocation regardless of
# the shortcut's target path. Skips gracefully on access-denied (Public Desktop
# entries created by an installer require elevation).
#
# Run normal:    powershell -ExecutionPolicy Bypass -File refresh_desktop_icons.ps1
# Run as admin:  Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File 'refresh_desktop_icons.ps1'"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$desktops  = @(
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("CommonDesktopDirectory")
)

$root          = $scriptDir
$sentinelIcons = Join-Path $scriptDir "sentinel\icons"
$sentinelRoot  = Join-Path $scriptDir "sentinel"

# Module → icon mapping. First match wins (top-down).
# Patterns are intentionally STRICT: must explicitly mention a suite-specific
# name. Generic words like "recorder" or "cleaner" alone are NOT enough — they'd
# false-match third-party apps (Total PC Cleaner, VSDC Screen Recorder, etc.).
$rules = @(
    @{ Match = "(?i)netguard.?ai|\bAI assistant\b"      ; Icon = (Join-Path $root          "netguard_ai_icon.ico") },
    @{ Match = "(?i)mail.?shield"                       ; Icon = (Join-Path $sentinelIcons "mailshield.ico") },
    @{ Match = "(?i)session.?recorder"                  ; Icon = (Join-Path $sentinelIcons "recorder.ico") },
    @{ Match = "(?i)honey.?pot.*agent|\bhoneypot\b"     ; Icon = (Join-Path $sentinelIcons "honeypot.ico") },
    @{ Match = "(?i)file.?integrity|\bFIM\b"            ; Icon = (Join-Path $sentinelIcons "fim.ico") },
    @{ Match = "(?i)strike.?back|red.?team.?toolkit"    ; Icon = (Join-Path $sentinelIcons "strikeback.ico") },
    @{ Match = "(?i)sandbox.?analyzer"                  ; Icon = (Join-Path $sentinelIcons "sandbox.ico") },
    @{ Match = "(?i)clean.?guard"                       ; Icon = (Join-Path $sentinelIcons "cleanguard.ico") },
    @{ Match = "(?i)siem.?monitor"                      ; Icon = (Join-Path $sentinelIcons "siem.ico") },
    @{ Match = "(?i)sentinel.?os|sentinelos"            ; Icon = (Join-Path $sentinelRoot  "SentinelOS.ico") },
    @{ Match = "(?i)vpn.?guard"                         ; Icon = (Join-Path $sentinelIcons "vpnguard.ico") },
    @{ Match = "(?i)\bnet.?guard\b"                     ; Icon = (Join-Path $root          "netguard_icon.ico") }
)

function Resolve-Icon($name) {
    foreach ($r in $rules) {
        if ($name -match $r.Match -and (Test-Path $r.Icon)) { return $r.Icon }
    }
    return $null
}

function Set-LnkIcon($lnkPath, $iconPath) {
    try {
        $sh = New-Object -ComObject WScript.Shell
        $sc = $sh.CreateShortcut($lnkPath)
        $sc.IconLocation = "$iconPath,0"
        $sc.Save()
        return @{ ok = $true }
    } catch {
        return @{ ok = $false; err = $_.Exception.Message }
    }
}

$total       = 0
$updated     = 0
$denied      = @()
$noMatch     = 0

foreach ($desktop in $desktops) {
    if (-not (Test-Path $desktop)) { continue }
    $links = Get-ChildItem -Path $desktop -Filter *.lnk -File -ErrorAction SilentlyContinue
    foreach ($lnk in $links) {
        $total++
        $base = [IO.Path]::GetFileNameWithoutExtension($lnk.Name)
        $icon = Resolve-Icon $base
        if (-not $icon) { $noMatch++; continue }

        $res = Set-LnkIcon $lnk.FullName $icon
        if ($res.ok) {
            $updated++
            $scope = if ($desktop -like "$env:PUBLIC*") { "[PUB]" } else { "[USR]" }
            Write-Host ("{0} {1,-32} -> {2}" -f $scope, $lnk.Name, [IO.Path]::GetFileName($icon)) -ForegroundColor Green
        } else {
            $denied += [pscustomobject]@{ Path = $lnk.FullName; Icon = $icon; Err = $res.err }
            Write-Host ("[!]   {0,-32} : access denied (admin requis)" -f $lnk.Name) -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host ("=== {0} icone(s) mises a jour / {1} raccourci(s) scannes / {2} ignores (non-NetGuard) / {3} access-denied ===" -f $updated, $total, $noMatch, $denied.Count) -ForegroundColor Cyan

# Force aggressive icon cache refresh
ie4uinit.exe -show 2>$null
Start-Sleep -Milliseconds 200
ie4uinit.exe -ClearIconCache 2>$null

if ($denied.Count -gt 0) {
    Write-Host ""
    Write-Host "Pour mettre a jour les raccourcis Public Desktop (Admin only), relance ce script en mode administrateur :" -ForegroundColor Yellow
    Write-Host "  Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"'" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "Raccourcis bloques :" -ForegroundColor Yellow
    foreach ($d in $denied) {
        Write-Host ("  - {0}" -f $d.Path) -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "[OK] Si certaines icones restent vieilles a l'ecran, fais Logout/Login pour vider le cache shell." -ForegroundColor Cyan
