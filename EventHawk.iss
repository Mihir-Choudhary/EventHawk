; EventHawk - Inno Setup 6 installer
; Bundles a portable, code-signed embeddable CPython 3.12 + PySide6/Qt app.
; Works for BOTH admin (all users -> Program Files) and non-admin (current user
; -> LocalAppData); the user chooses at install time. Creates one-click shortcuts.
;
; SourceDir = the portable bundle produced by build_standalone.ps1. Override at
; compile time:  ISCC.exe /DSourceDir=C:\path\to\EventHawk EventHawk.iss
#ifndef SourceDir
  #define SourceDir "build\EventHawk"
#endif

#define MyAppName        "EventHawk"
; build_standalone.ps1 passes /DMyAppVersion=<evtx_tool.__version__>.
#ifndef MyAppVersion
  #define MyAppVersion   "2.0.0"
#endif
#define MyAppPublisher   "Mihir Singh Choudhary"
#define MyAppURL         "https://github.com/Mihir-Choudhary/EventHawk"
#define MyAppExeName     "pythonw.exe"
#define MyAppEntryScript "eventhawk_gui.py"
#define MyAppIcon        "EventHawk.ico"

[Setup]
AppId={{B8E7A4D3-2C1F-4A5E-9D6B-3E8F1A2C4D5E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Non-admin friendly: default to a per-user install (no UAC prompt, goes to
; LocalAppData). The user may elevate and install for all users (Program Files)
; via the install-mode dialog. {autopf}/{autodesktop}/{group} follow the choice.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#SourceDir}\EventHawk.ico
UninstallDisplayIcon={app}\{#MyAppIcon}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
OutputBaseFilename=EventHawk-{#MyAppVersion}-Setup
OutputDir=Output

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Parameters: """{app}\{#MyAppEntryScript}"" gui"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppIcon}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Parameters: """{app}\{#MyAppEntryScript}"" gui"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppIcon}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: """{app}\{#MyAppEntryScript}"" gui"; WorkingDir: "{app}"; \
    Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[InstallDelete]
; An upgrade replaces the program's code whole: files a newer version no longer
; has (a removed module) would otherwise stay and could still be imported.
Type: filesandordirs; Name: "{app}\evtx_tool"
Type: filesandordirs; Name: "{app}\sentinel"
Type: filesandordirs; Name: "{app}\Lib"

[UninstallDelete]
; Program files only.  %LOCALAPPDATA%\EventHawk is the analyst's own data (custom
; profiles, logs, Sentinel's baseline key): uninstalling, or reinstalling,
; deleted it, so every saved baseline had to be rebuilt.  It is kept.
Type: filesandordirs; Name: "{app}\evtx_tool\__pycache__"
Type: filesandordirs; Name: "{app}\sentinel\__pycache__"
