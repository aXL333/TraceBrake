; Inno Setup script for Foreman Agent Safety -- per-user, no-admin installer.
; Build locally:   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DMyAppVersion=0.1.0 installer\foreman.iss
; CI passes the version via /DMyAppVersion=... (see .github/workflows/release.yml).

#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
#define MyAppName "Foreman Agent Safety"
#define MyAppInstallDirName "Foreman"
#define MyAppPublisher "aXL333"
#define MyAppURL "https://github.com/aXL333/Foreman"
#define MyAppExeName "Foreman.exe"

[Setup]
; Stable GUID so upgrades replace the existing install rather than stacking.
AppId={{C2F5A8E1-7B3D-4E6A-9C1F-3A8B5D2E7F40}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
; Install per-user so no UAC prompt is required.
PrivilegesRequired=lowest
; Keep immutable program files separate from Foreman's mutable settings/vault/log data in
; %LOCALAPPDATA%\Foreman. Inno retains the previous directory for existing upgrades.
DefaultDirName={localappdata}\Programs\{#MyAppInstallDirName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=Foreman-Agent-Safety-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Foreman already owns this named mutex. Refuse install/upgrade while the tray app is running rather than
; replacing a live executable or leaving a reboot-pending mixture of versions.
AppMutex=ForemanSingleInstanceMutex

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "startup";     Description: "Start Foreman Agent Safety automatically when I sign in"; GroupDescription: "Startup:";   Flags: checkedonce
Name: "desktopicon"; Description: "Create a desktop shortcut";                  GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
; Copy everything the publish step produced (single-file exe plus any extracted natives).
Source: "..\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Prevent removed extension/helper files from surviving an upgrade and tripping the exact runtime manifest.
Type: filesandordirs; Name: "{app}\extensions"
Type: filesandordirs; Name: "{app}\sidecar"
Type: filesandordirs; Name: "{app}\guardian"
Type: filesandordirs; Name: "{app}\cu-sidecar"
Type: filesandordirs; Name: "{app}\cu-pilot"

[Icons]
Name: "{autoprograms}\{#MyAppName}";   Filename: "{app}\{#MyAppExeName}"
Name: "{userdesktop}\{#MyAppName}";    Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Optional run-at-login entry under HKCU (no admin needed); removed on uninstall.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; \
    ValueName: "Foreman Agent Safety"; ValueData: """{app}\{#MyAppExeName}"""; \
    Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Foreman Agent Safety now"; Flags: nowait postinstall skipifsilent

[Code]
// If the opt-in hardened guardian (a LocalSystem service) was installed, remove it BEFORE files are deleted.
// The per-user uninstaller isn't elevated, so we ShellExec the guardian's own --uninstall with 'runas' (one UAC,
// only when the guardian binary is actually present). If declined, the leftover service is inert and removable
// later via 'sc delete Foreman.Guardian'.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  GuardianExe: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    GuardianExe := ExpandConstant('{commonpf}\Foreman\guardian\Foreman.Guardian.exe');
    if FileExists(GuardianExe) then
      ShellExec('runas', GuardianExe, '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
