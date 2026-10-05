; NetGuard AI — installateur Windows (Inno Setup 6)
; Construit par packaging\build_exe.ps1 : ISCC /DAppVersion=… /DSourceDir=… /DOutputDir=… NetGuardAI.iss

#ifndef AppVersion
  #define AppVersion "4.2.2"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\NetGuardAI"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
AppId={{6F1B6C0E-6D0B-4A53-9C59-3E5B7F0A4A11}
AppName=NetGuard AI
AppVersion={#AppVersion}
AppVerName=NetGuard AI {#AppVersion}
AppPublisher=Archipel AI
DefaultDirName={autopf}\NetGuard AI
DefaultGroupName=NetGuard AI
DisableProgramGroupPage=yes
LicenseFile={#SourceDir}\_internal\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename=NetGuardAI-Setup-{#AppVersion}
SetupIconFile={#SourceDir}\_internal\netguard_icon.ico
UninstallDisplayIcon={app}\NetGuardAI.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
CloseApplications=yes

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NetGuard AI"; Filename: "{app}\NetGuardAI.exe"
Name: "{group}\{cm:UninstallProgram,NetGuard AI}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\NetGuard AI"; Filename: "{app}\NetGuardAI.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NetGuardAI.exe"; Description: "{cm:LaunchProgram,NetGuard AI}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; Retire toutes les règles de pare-feu NetGuard_* posées pendant l'utilisation
Filename: "{app}\NetGuardAI.exe"; Parameters: "--remove-firewall-rules"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveNetGuardRules"
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -Command ""Get-NetFirewallRule -DisplayName 'NetGuard_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveNetGuardRulesPS"

[UninstallDelete]
; Les données de l'utilisateur (%LOCALAPPDATA%\NetGuard AI) sont volontairement conservées.
Type: filesandordirs; Name: "{app}"
