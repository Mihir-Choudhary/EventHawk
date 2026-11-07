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

**Large dataset (fewer worker processes, lower memory pressure):**

```bat
py -3 evtx_tool.py parse C:\LargeCapture ^
    --max-threads 8 ^
    --no-tui ^
    --output results.json
```

Juggernaut Mode (the columnar engine) is a GUI mode; the CLI has no switch for it.

**With text search:**

```bat
py -3 evtx_tool.py parse C:\Logs ^
    --search "mimikatz" ^
    --output suspicious.json
```

**Full example:**

```bat
py -3 evtx_tool.py parse C:\Logs ^
    --profile "Process Creation and Termination" ^
    --event-id 4688,1 ^
    --level warning,error,critical ^
    --computer DC01 ^
    --date-from "2025-05-10T00:00:00" ^
    --date-to "2025-05-10T23:59:59" ^
    --search "powershell" ^
    --ioc --correlate ^
    --output results.json ^
    --max-threads 6
```

**Options reference** (`py -3 evtx_tool.py parse --help` lists the same):

| Option | Description |
|---|---|
| `-p, --profile NAME` | Apply a DFIR profile by name or by the path of a `.json` profile file; repeat for several, or `all`. A name or file that does not exist stops the run with an error (exit 2) |
| `-F, --filter-file FILE` | Load a filter saved with `--save-filter` (or from the GUI's Advanced Filter) |
| `-e, --event-id LIST` | Event IDs or ranges, e.g. `4624,4625` or `4600-4650` |
| `--exclude-id LIST` | Event IDs to leave out |
| `-l, --level LIST` | `critical,error,warning,info,verbose` |
| `--date-from`, `--date-to` | Time range (ISO 8601, e.g. `2025-05-10T14:30:00`) |
| `-u, --user TEXT` | Username or SID |
| `-c, --computer TEXT` | Computer name |
| `-s, --source TEXT` | Source / provider |
| `-q, --search TEXT` | Free-text search terms |
| `--search-mode` | `and` (default), `or`, `not` |
| `--timeline-anchor`, `--timeline-before`, `--timeline-after` | A time window around a moment (minutes before / after; defaults 5 / 30) |
| `-o, --output FILE` | Output file (`.html`, `.csv`, `.json`, `.xml`, `.pdf`) |
| `--format` | Override the output format: `csv`, `json`, `xml`, `html`, `pdf` |
| `--save-filter FILE` | Save the active filter (including applied profiles) to a JSON file |
| `--attack / --no-attack` | ATT&CK tagging (on by default) |
| `--ioc` | Extract IOCs |
| `--correlate` | Run the attack-chain correlation engine |
| `--max-threads N` | Maximum worker processes (default: CPU count - 1) |
| `--cpu-limit`, `--ram-limit`, `--priority` | Resource limits and process priority |
| `--no-recursive` | Do not search sub-folders |
| `--limit N` | Write at most N events |
| `--no-tui` | No terminal dashboard |
| `-v, --verbose` | More logging |

---

### `diff` — Compare two sets of logs

Parses a baseline set and an incident set of EVTX files (files or folders) and lists the event types that are NEW in the incident, the ones MISSING from it, and VOLUME SPIKES and DROPS.

```bat
py -3 evtx_tool.py diff C:\Baseline C:\Incident --output diff.html
```

**Options reference** (`py -3 evtx_tool.py diff --help`):

| Option | Description |
|---|---|
| `-p, --profile NAME` | Profiles applied to both sets (name or `.json` path, or `all`); an unknown one stops the run |
| `-o, --output FILE` | Output file (`.html`, `.json`, `.csv`) |
| `--format` | `csv`, `json`, `xml`, `html`, `pdf` |
| `--spike-factor X` | Incident/baseline ratio counted as a spike (default 3.0) |
| `--max-threads N` | Maximum worker processes |
| `-v, --verbose` | More logging |

To look at a time window around one moment, use `parse` with `--timeline-anchor`, `--timeline-before` and `--timeline-after`.

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
py -3 evtx_tool.py benchmark C:\Logs --threads 4
```

Sample output:
```
EventHawk v1.3 — Benchmark
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

- The CLI does not support all GUI filter combinations (e.g. the layered filter stack is simplified in CLI mode to single-pass filtering).
- Interactive mode does not persist between runs.
- PDF export from the CLI includes ATT&CK, IOC and chain sections only when `--attack`, `--ioc` and `--correlate` ran.
- Timestamp parsing for `--date-from`, `--date-to` and `--timeline-anchor` supports: ISO 8601 with or without microseconds, with or without trailing `Z`, and space-separated formats (`2025-05-10 14:30:00`).

---

## Related Docs

- [TUI Mode](13-tui.md)
- [DFIR Profiles](14-profiles.md)
- [Normal Mode](03-normal-mode.md)
- [Juggernaut Mode](04-juggernaut-mode.md)
- [Exporting](11-exporting.md)
