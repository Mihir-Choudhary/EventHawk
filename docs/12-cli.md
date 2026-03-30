# CLI Mode

## What It Is

EventHawk includes a full headless command-line interface for scripting, automation, server environments, and workflows where a GUI is not desired. All parsing, filtering, analysis, and export features available in the GUI are accessible from the CLI.

---

## Entry Point

```bat
py -3 evtx_tool.py [COMMAND] [OPTIONS]
```

Run `--help` on any command for the full option list:

```bat
py -3 evtx_tool.py --help
py -3 evtx_tool.py parse --help
```

---

## Commands

### `parse` — Parse EVTX files

The core command. Parses one or more EVTX files or a folder, applies optional filters, runs analysis, and exports results.

**Basic usage:**

```bat
py -3 evtx_tool.py parse C:\Logs\Security.evtx
```

**Parse a folder with a DFIR profile:**

```bat
py -3 evtx_tool.py parse C:\Windows\System32\winevt\Logs ^
    --profile "Logon/Logoff Activity" ^
    --output results.json
```

**Filter by event ID and level:**

```bat
py -3 evtx_tool.py parse C:\Logs ^
    --event-id 4624,4625,4648 ^
    --level warning,error,critical ^
    --output results.csv ^
    --format csv
```

**Juggernaut Mode (large dataset):**

```bat
py -3 evtx_tool.py parse C:\LargeCapture ^
    --juggernaut ^
    --workers 8 ^
    --output results.json
```

**With text search:**

```bat
py -3 evtx_tool.py parse C:\Logs ^
    --search "mimikatz" ^
    --output suspicious.json
```

**Full example with all options:**

```bat
py -3 evtx_tool.py parse C:\Logs ^
    --profile "Process Creation" ^
    --event-id 4688,1 ^
    --level warning,error,critical ^
    --computer DC01 ^
    --from "2025-05-10T00:00:00" ^
    --to "2025-05-10T23:59:59" ^
    --search "powershell" ^
    --output results.json ^
    --format json ^
    --workers 6 ^
    --tui
```

**Options reference:**

| Option | Description |
|---|---|
| `--profile NAME` | Apply a DFIR profile by name or path to a `.json` profile file |
| `--event-id LIST` | Comma-separated event IDs or range (e.g. `4624,4625` or `4600-4700`) |
| `--level LIST` | Comma-separated levels: `critical,error,warning,information,verbose` |
| `--computer TEXT` | Filter by computer name (substring) |
| `--from TIMESTAMP` | Start of time range (ISO 8601, e.g. `2025-05-10T14:30:00`) |
| `--to TIMESTAMP` | End of time range |
| `--search TEXT` | Full-text search across all event fields |
| `--search-mode` | `contains` (default) or `regex` |
| `--output FILE` | Save results to a file |
| `--format` | Output format: `json` (default), `csv`, `xml`, `html`, `pdf` |
| `--juggernaut` | Enable Juggernaut Mode (columnar engine for large datasets) |
| `--workers N` | Number of parse worker processes (default: CPU count − 1) |
| `--tui` | Show the Rich terminal dashboard during parsing |
| `--no-analysis` | Skip ATT&CK/IOC/chain analysis (faster) |

---

### `diff` — Compare two captures or time windows

Compares two parse results or defines a time window around a known event.

**Compare two JSON outputs:**

```bat
py -3 evtx_tool.py diff baseline.json incident.json
```

**Timeline window around a specific timestamp:**

Shows all events in a time window centred on a known event (useful for investigation pivoting):

```bat
py -3 evtx_tool.py diff ^
    --anchor "2025-05-10T18:08:16.313420Z" ^
    --before 30 ^
    --after 60 ^
    C:\Logs
```

This shows events from 30 minutes before to 60 minutes after the anchor timestamp.

**Options reference:**

| Option | Description |
|---|---|
| `--anchor TIMESTAMP` | Central event timestamp (ISO 8601, microseconds and Z suffix supported) |
| `--before N` | Minutes before the anchor to include (default: 30) |
| `--after N` | Minutes after the anchor to include (default: 30) |
| `--output FILE` | Save diff output to a file |

---

### `profiles` — Manage DFIR profiles

List, inspect, or validate profiles.

**List all built-in profiles:**

```bat
py -3 evtx_tool.py profiles list
```

Output:
```
 #  Name                         Event IDs           Description
 1  User Account Management      4720,4722,4724…     Track user creation, modification, deletion
 2  Logon/Logoff Activity        4624,4625,4634…     All authentication events
 3  Privilege Escalation         4672,4673,4674…     Privilege use and assignment
...
20  Boot / Shutdown              1074,6006,6008…     System start/stop and crashes
```

**Show full details of a specific profile:**

```bat
py -3 evtx_tool.py profiles show "Process Creation"
```

**Validate a custom profile file:**

```bat
py -3 evtx_tool.py profiles validate my_profile.json
```

---

### `benchmark` — Measure parse performance

Parses a folder and reports throughput statistics without saving output. Useful for sizing hardware or comparing configurations.

```bat
py -3 evtx_tool.py benchmark C:\Logs --workers 4
```

Sample output:
```
EventHawk v1.2 — Benchmark
Files: 47  |  Total size: 8.4 GB
Workers: 6 (auto)

  Parsing...  ████████████████████  100%  18.3 s
  Events matched:  1,621,044
  Throughput:      88,581 events/sec
  Peak RAM:        412 MB
  Peak CPU:        94%
```

---

### `interactive` — Interactive REPL

Starts an interactive session where you can run multiple queries against the same loaded dataset without re-parsing.

```bat
py -3 evtx_tool.py interactive
```

Inside the REPL:
```
EventHawk> load C:\Logs
Parsing... done. 1,621,044 events loaded.
EventHawk> filter --event-id 4624 --computer DC01
Filtered: 4,231 events
EventHawk> export --format csv --output logons.csv
Exported: logons.csv
EventHawk> exit
```

---

### `gui` — Launch the Desktop GUI

```bat
py -3 evtx_tool.py gui
```

Launches the full PySide6 desktop application. Equivalent to double-clicking `EventHawk.exe`.

---

## Limitations

- The CLI does not support all GUI filter combinations (e.g. the 4-layer filter stack is simplified in CLI mode to single-pass filtering).
- Interactive mode does not persist between runs.
- `--tui` and `--juggernaut` cannot be used simultaneously in this version.
- PDF export from CLI requires all analysis modules to have run — use without `--no-analysis`.
- Timestamp parsing for `--from`, `--to`, and `--anchor` supports: ISO 8601 with or without microseconds, with or without trailing `Z`, and space-separated formats (`2025-05-10 14:30:00`).

---

## Related Docs

- [TUI Mode](13-tui.md)
- [DFIR Profiles](14-profiles.md)
- [Normal Mode](03-normal-mode.md)
- [Juggernaut Mode](04-juggernaut-mode.md)
- [Exporting](11-exporting.md)
