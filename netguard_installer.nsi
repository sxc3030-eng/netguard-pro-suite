; NetGuard AI — Script installateur NSIS
; Télécharge NSIS: https://nsis.sourceforge.io/Download
; Compile avec: makensis netguard_installer.nsi

!define APP_NAME "NetGuard AI"
!define APP_VERSION "4.2.0"
!define APP_PUBLISHER "NetGuard AI"
!define APP_URL "https://github.com/sxc3030-eng/netguard-pro"
!define APP_EXE "NetGuardAI.exe"
!define INSTALL_DIR "$PROGRAMFILES64\NetGuard AI"

; Inclure les modules NSIS
!include "MUI2.nsh"
!include "FileFunc.nsh"

; Configuration générale
Name "${APP_NAME} ${APP_VERSION}"
OutFile "NetGuardPro_Setup_v${APP_VERSION}.exe"
InstallDir "${INSTALL_DIR}"
InstallDirRegKey HKLM "Software\${APP_NAME}" "Install_Dir"
RequestExecutionLevel admin
BrandingText "${APP_NAME} v${APP_VERSION}"

; Interface moderne
!define MUI_ABORTWARNING
!define MUI_ICON "netguard_icon.ico"
!define MUI_UNICON "netguard_icon.ico"
!define MUI_HEADERIMAGE
!define MUI_WELCOMEFINISHPAGE_BITMAP "installer_banner.bmp"

; Couleurs
!define MUI_BGCOLOR "161620"
!define MUI_TEXTCOLOR "E8E8F0"

; Pages d'installation
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Pages de désinstallation
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Langue
!insertmacro MUI_LANGUAGE "French"

; ─── Installation ──────────────────────────────────────────────────────────
Section "NetGuard AI (requis)" SecMain
    SectionIn RO
    SetOutPath "$INSTDIR"

    ; Fichiers principaux
    File "dist\NetGuardAI.exe"
    File "netguard_dashboard.html"
    File "netguard_login.html"
    File "netguard_map.html"
    File "netguard_panels.html"
    File "netguard_history.html"
    File "netguard_analyze.html"
    File "netguard_service.html"
    File "netguard_tray.py"

    ; Créer le dossier captures
    CreateDirectory "$INSTDIR\captures"
    CreateDirectory "$INSTDIR\logs"

    ; Créer le lanceur principal
    FileOpen $0 "$INSTDIR\Lancer_NetGuard.bat" w
    FileWrite $0 "@echo off$\r$\n"
    FileWrite $0 "title NetGuard AI v3.0$\r$\n"
    FileWrite $0 "cd /d $\"$INSTDIR$\"$\r$\n"
    FileWrite $0 "echo Démarrage de NetGuard AI...$\r$\n"
    FileWrite $0 "$\"$INSTDIR\NetGuardAI.exe$\" --demo$\r$\n"
    FileClose $0

    ; Raccourcis Bureau
    CreateShortcut "$DESKTOP\NetGuard AI.lnk" \
        "$INSTDIR\NetGuardAI.exe" "--demo" \
        "$INSTDIR\NetGuardAI.exe" 0 \
        SW_SHOWNORMAL "" "NetGuard AI — Protection réseau"

    ; Menu Démarrer
    CreateDirectory "$SMPROGRAMS\NetGuard AI"
    CreateShortcut "$SMPROGRAMS\NetGuard AI\NetGuard AI.lnk" \
        "$INSTDIR\NetGuardAI.exe" "--demo" \
        "$INSTDIR\NetGuardAI.exe" 0
    CreateShortcut "$SMPROGRAMS\NetGuard AI\Dashboard.lnk" \
        "$INSTDIR\netguard_dashboard.html"
    CreateShortcut "$SMPROGRAMS\NetGuard AI\Désinstaller.lnk" \
        "$INSTDIR\Uninstall.exe"

    ; Registre Windows
    WriteRegStr HKLM "Software\${APP_NAME}" "Install_Dir" "$INSTDIR"
    WriteRegStr HKLM "Software\${APP_NAME}" "Version" "${APP_VERSION}"

    ; Ajout dans "Programmes et fonctionnalités"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "DisplayName" "${APP_NAME}"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "Publisher" "${APP_PUBLISHER}"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "URLInfoAbout" "${APP_URL}"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "UninstallString" "$INSTDIR\Uninstall.exe"
    WriteRegDWORD HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "NoModify" 1
    WriteRegDWORD HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "NoRepair" 1

    ; Créer le désinstalleur
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Installer le service Windows (tâche planifiée)
    ExecWait 'powershell -WindowStyle Hidden -Command "$action = New-ScheduledTaskAction -Execute \"$INSTDIR\NetGuardAI.exe\"; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -TaskName \"NetGuardAI\" -Action $action -Trigger $trigger -RunLevel Highest -Force"'

SectionEnd

; ─── Désinstallation ────────────────────────────────────────────────────────
Section "Uninstall"
    ; Arrêter le service
    ExecWait 'powershell -WindowStyle Hidden -Command "Stop-ScheduledTask -TaskName NetGuardAI -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName NetGuardAI -Confirm:$false -ErrorAction SilentlyContinue"'
    ; Retirer toutes les règles pare-feu NetGuard_* ajoutées pendant l'utilisation
    ExecWait '"$INSTDIR\NetGuardAI.exe" --remove-firewall-rules'
    ExecWait 'powershell -WindowStyle Hidden -Command "Get-NetFirewallRule -DisplayName NetGuard_* -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue"'

    ; Supprimer les fichiers
    Delete "$INSTDIR\NetGuardAI.exe"
    Delete "$INSTDIR\*.html"
    Delete "$INSTDIR\*.bat"
    Delete "$INSTDIR\*.py"
    Delete "$INSTDIR\*.json"
    Delete "$INSTDIR\*.pem"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR\captures"
    RMDir "$INSTDIR\logs"
    RMDir "$INSTDIR"

    ; Supprimer raccourcis
    Delete "$DESKTOP\NetGuard AI.lnk"
    Delete "$SMPROGRAMS\NetGuard AI\*.*"
    RMDir "$SMPROGRAMS\NetGuard AI"

    ; Nettoyer le registre
    DeleteRegKey HKLM "Software\${APP_NAME}"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

SectionEnd
