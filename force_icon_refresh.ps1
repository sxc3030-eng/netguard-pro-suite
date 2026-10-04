# NetGuard AI Suite — Aggressive Windows icon cache flush.
# Run when desktop / taskbar still shows old icons after replacing .ico files.
#
# Effects:
#   1. Stop all explorer.exe processes (your desktop will blink).
#   2. Delete every iconcache_*.db Windows uses for the shell.
#   3. Restart explorer.exe.
#
# Run: powershell -ExecutionPolicy Bypass -File force_icon_refresh.ps1

Write-Host "[*] Stopping Explorer (desktop will blink)..." -ForegroundColor Yellow
$explorers = Get-Process -Name explorer -ErrorAction SilentlyContinue
if ($explorers) {
    $explorers | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 700
}

$caches = @(
    (Join-Path $env:LOCALAPPDATA "IconCache.db"),
    (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer")
)

Write-Host "[*] Deleting icon caches..." -ForegroundColor Yellow
$deleted = 0

# Single-file IconCache.db
$single = Join-Path $env:LOCALAPPDATA "IconCache.db"
if (Test-Path $single) {
    try { Remove-Item -Path $single -Force -ErrorAction Stop; $deleted++ } catch {}
}

# Win10/11 split iconcache_*.db files
$split = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"
if (Test-Path $split) {
    Get-ChildItem -Path $split -Filter "iconcache_*.db" -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item -Path $_.FullName -Force -ErrorAction Stop; $deleted++ } catch {}
    }
    Get-ChildItem -Path $split -Filter "thumbcache_*.db" -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item -Path $_.FullName -Force -ErrorAction Stop; $deleted++ } catch {}
    }
}

Write-Host "[OK] $deleted cache file(s) deleted." -ForegroundColor Green

Write-Host "[*] Restarting Explorer..." -ForegroundColor Yellow
Start-Process explorer.exe
Start-Sleep -Milliseconds 500

# Touch each .lnk on the desktops so Windows re-reads them after explorer comes back.
$desktops = @(
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("CommonDesktopDirectory")
)
foreach ($desktop in $desktops) {
    if (-not (Test-Path $desktop)) { continue }
    Get-ChildItem -Path $desktop -Filter *.lnk -File -ErrorAction SilentlyContinue | ForEach-Object {
        try { (Get-Item $_.FullName -ErrorAction Stop).LastWriteTime = Get-Date } catch {}
    }
}

Write-Host ""
Write-Host "=== Icon cache flushed. Desktop should now show the new icons. ===" -ForegroundColor Cyan
Write-Host "Si certaines icones restent vieilles : 1) ferme NetGuard (sa fenetre cache son icone)" -ForegroundColor Cyan
Write-Host "                                       2) sinon Logout/Login Windows pour refresh complet." -ForegroundColor Cyan
