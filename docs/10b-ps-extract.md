# PowerShell History Extraction

## What It Does

The **PowerShell History** feature reconstructs the full PowerShell activity recorded in a set of EVTX files — sessions, commands, script blocks, and execution metadata — into five structured output files ready for investigation or SIEM ingestion.

It parses six event IDs from the Windows PowerShell and Microsoft-Windows-PowerShell/Operational channels:

| Event ID | Channel | What It Records |
|----------|---------|-----------------|
| 400 | Windows PowerShell | Engine started — host app, version, runspace |
| 403 | Windows PowerShell | Engine stopped — duration |
| 600 | Windows PowerShell | Provider loaded (FileSystem, Registry, etc.) |
| 800 | Windows PowerShell | Pipeline executed — command line detail |
| 4103 | PowerShell/Operational | Command invocation — module logging |
| 4104 | PowerShell/Operational | Script block — full source text (multi-fragment) |

> **Note:** PS History is a GUI-only feature. It is not available from the CLI.

---

## Prerequisites

PowerShell logging must have been enabled on the source system before the incident occurred. Without the right audit policy, events will not be present in the EVTX files.

| What you need | Where to enable it |
|---|---|
| EID 4103 (module logging) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` → `EnableModuleLogging = 1` |
| EID 4104 (script block logging) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` → `EnableScriptBlockLogging = 1` |
| EID 400/403/600/800 | Enabled by default when PowerShell is installed — no policy change needed |

If only EID 400/403 are present, session metadata will be available but no command content. If EID 4104 is present, full script block text is available.

---

## How to Run

1. Load your EVTX files via **Normal Mode** or **Juggernaut Mode** as usual.
2. From the menu bar, click **Analysis → PowerShell History**.
3. A folder picker appears — choose an **empty output directory** for the extracted files.
4. The extraction progress dialog appears showing live progress. Click **Cancel** at any time to abort cleanly.
5. When complete, a summary dialog lists all output files and a **Open Folder** button opens the output directory in Explorer.

---

## Output Files

All five files are written to the output directory you chose.

### `ps_commands.txt`

Chronological human-readable timeline of all PowerShell sessions and their commands. Each session block shows:

```
================================================================================
SESSION: {HostId}
================================================================================
  Host Application : powershell.exe -NonInteractive -EncodedCommand ...
  Host Name        : ConsoleHost
  Host Version     : 5.1.19041.4648
  Engine Version   : 5.1.19041.4648
  Started          : 2025-07-05 05:06:54.459730
  Ended            : 2025-07-05 05:07:12.001004
  Duration         : 0:00:17
  PID              : 4832
  User SID         : S-1-5-21-...
  User Name        : CORP\john.doe
  Source File      : C:\Evidence\Security.evtx

Events (3):
  [2025-07-05 05:06:54] EID 400  ENGINE_START
  [2025-07-05 05:06:55] EID 4104 SCRIPT_BLOCK  Path: C:\Scripts\recon.ps1
      Content: param($target) $results = Invoke-Command -ComputerName $target ... [4,821 chars — see scriptblock_abc123….txt]
  [2025-07-05 05:07:12] EID 403  ENGINE_STOP
```

### `scriptblock_<GUID>.txt`

One file per unique script block ID. Contains the fully reassembled script block source — even if it was split across multiple EID 4104 events (large scripts are fragmented by PowerShell). The file header shows metadata:

```
Script Block ID : {3fa85f64-5717-4562-b3fc-2c963f66afa6}
Path            : C:\Scripts\recon.ps1
Flags           : [FIRST_FRAGMENT] [LAST_FRAGMENT]
Fragments       : 3 / 3
Timestamp       : 2025-07-05 05:06:55.123456
ATT&CK          : T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)
Risk Flags      : ENCODED_COMMAND, BYPASS_EXECUTION_POLICY
--------------------------------------------------------------------------------
<full script text>
```

### `ps_extraction_summary.txt`

Statistics overview:

- Total sessions (real vs ghost), commands, script blocks
- Source files that contained PS events
- ATT&CK techniques detected across all script blocks
- Risk flag breakdown (encoded commands, AMSI bypass attempts, etc.)

### `ps_extraction.json`

Machine-readable export for SIEM ingestion or further scripting. Contains:

- Full session objects with metadata
- Per-session event list with all parsed fields
- Script block index with content, metadata, and ATT&CK annotations
- Source file list (only files that contained PS events)

### `ps_timeline.xlsx`

Flat chronological event timeline in Excel format. Columns:

| Column | Description |
|--------|-------------|
| timestamp | `YYYY-MM-DD HH:MM:SS.ffffff` |
| event_id | 400 / 403 / 600 / 800 / 4103 / 4104 |
| event_type | ENGINE_START / COMMAND_EXEC / SCRIPT_BLOCK etc. |
| pid | Process ID |
| session_id | HostId linking back to ps_commands.txt |
| user_sid | User SID from event |
| user_name | Domain\Username |
| command | Command name, provider, or script path |
| script_block_id | GUID (EID 4104 rows only) |
| script_block_file | Clickable hyperlink → opens `scriptblock_<GUID>.txt` |
| detail | Short context: command line, payload excerpt, host app (500 char cap) |

The `script_block_file` column contains **native Excel hyperlinks** — click the cell to open the corresponding `.txt` file directly from the output folder.

---

## ATT&CK Detection

EventHawk maps patterns found in script block content to MITRE ATT&CK techniques automatically:

| Technique | What Triggers It |
|-----------|-----------------|
| T1059.001 — PowerShell | Any EID 4104 script block |
| T1027 — Obfuscation | Base64 blobs, char-code concatenation, string reversal, tick escapes |
| T1562.001 — Disable Defenses | Set-MpPreference, Add-MpPreference, AMSI bypass patterns |
| T1003 — Credential Dumping | Invoke-Mimikatz, sekurlsa, lsass references |
| T1055 — Process Injection | VirtualAlloc, WriteProcessMemory, CreateRemoteThread |
| T1086 — PowerShell (legacy) | Encoded -EncodedCommand invocations |
| T1105 — Ingress Tool Transfer | Invoke-WebRequest, WebClient.DownloadFile, BITS |
| T1053 — Scheduled Tasks | Register-ScheduledTask, schtasks |

Detected techniques appear in the script block files and the JSON export. They are not yet merged into the ATT&CK tab (that integration is on the roadmap).

---

## Ghost Sessions

Some EVTX files contain EID 400 records with entirely empty metadata (no host name, no host application) due to log corruption or aggressive log rotation. EventHawk automatically detects and filters these **ghost sessions** — they do not appear in `ps_commands.txt` or the JSON export. The summary file shows the ghost count separately.

A session is only filtered as a ghost if it meets all three criteria:
1. Host ID is a synthetic `_pid...` key (no real HostId in the event)
2. Both `host_name` and `host_application` are empty
3. The session contains one event or fewer

Sessions that meet criteria 1 but have correlated commands are kept — they are real sessions with a damaged ID.

---

## Limitations

- **PS logging must be pre-enabled** on the source system. EventHawk cannot reconstruct commands that were never logged.
- EID 4103 (module logging) produces one event per parameter binding — large loops generate many events. This is expected.
- EID 4104 script blocks can be fragmented across many events. EventHawk reassembles all fragments automatically using the `ScriptBlockId` + fragment index.
- If `ScriptBlockId` is all-zeros (a known PowerShell bug with certain host types), EventHawk uses the event record ID to disambiguate fragments.
- The Excel cell character limit is 32,767. Script block content in `ps_timeline.xlsx` is linked via hyperlink rather than embedded inline to avoid this limit.
- PS History is GUI-only — not available from the CLI or TUI.

---

## Related Docs

- [Analysis Tabs](09-analysis-tabs.md) — ATT&CK, IOC, and Chain tabs
- [Hayabusa Integration](10-hayabusa.md) — additional Sigma-rule-based detection
- [Exporting](11-exporting.md) — export formats for main event table
