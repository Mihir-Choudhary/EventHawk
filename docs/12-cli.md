# Command-line interface

Run PowerShell from the repository root. Example paths are placeholders; output parent folders must exist. Install source dependencies as described in [installation](01-installation.md).

```powershell
py -3.12 evtx_tool.py --help
py -3.12 evtx_tool.py parse --help
py -3.12 evtx_tool.py diff --help
py -3.12 evtx_tool.py profiles --help
py -3.12 evtx_tool.py benchmark --help
py -3.12 evtx_tool.py interactive --help
py -3.12 evtx_tool.py gui --help
```

## Parse

```powershell
py -3.12 evtx_tool.py parse .\logs --no-tui -o .\events.json
py -3.12 evtx_tool.py parse .\logs --profile "Process Creation and Termination" --ioc --correlate --no-tui -o .\report.html
py -3.12 evtx_tool.py parse .\logs --event-id 4624,4625 --exclude-id 4625 --no-tui -o .\logons.csv
py -3.12 evtx_tool.py parse .\logs --timeline-anchor "2026-01-01T12:00:00Z" --timeline-before 5 --timeline-after 30 --no-tui -o .\timeline.json
py -3.12 evtx_tool.py parse .\logs --profile .\process-profile.json --save-filter .\saved-filter.json --no-tui -o .\profiled.json
py -3.12 evtx_tool.py parse .\logs --filter-file .\saved-filter.json --no-tui -o .\reloaded.json
```

Use UTC for CLI boundaries. --timeline-anchor accepts the documented date/time forms with an optional trailing Z, but not numeric timezone offsets. Its computed bounds use whole seconds. --date-from/--date-to also compare whole seconds and do not convert numeric offsets; do not rely on offset or subsecond filtering here.

The JSON profile example is defined in [profiles](14-profiles.md). Supply a time that overlaps your own data; a valid time window can return no events.

| Option | Meaning / default |
|---|---|
| -p / --profile | Repeat names/JSON paths, or use all; profiles restrict matched output |
| -F / --filter-file | Load JSON filter restrictions |
| -e / --event-id | Include comma-separated IDs or ranges |
| --exclude-id | Exclude comma-separated integer IDs; ranges are not supported here |
| -l / --level | critical, error, warning, info, verbose |
| --date-from, --date-to | UTC wall-time boundaries, compared at whole-second granularity; convert offsets to UTC yourself |
| -u / --user, -c / --computer, -s / --source | Identity/provider restrictions |
| -q / --search, --search-mode | Text terms; AND, OR, NOT; default AND |
| --timeline-anchor, --timeline-before, --timeline-after | Time pivot; default 5 minutes before / 30 after |
| -o / --output, --format | Output path; csv/json/xml/html/pdf |
| --save-filter | Save filter configuration, not event data |
| --attack / --no-attack | ATT&CK tagging; enabled by default |
| --ioc, --correlate | Opt-in IOC extraction / correlation |
| --max-threads | Worker process limit; default CPU count minus one, at least one |
| --cpu-limit, --ram-limit | Resource-monitor settings; defaults 85 / 90 percent, not hard process-memory guarantees |
| --priority | low, normal, high; default normal |
| --no-recursive | Do not recursively discover subfolders |
| --limit | Limit output event count |
| --no-tui | Disable the live terminal dashboard |
| -v / --verbose | More detailed logging |

No GUI Juggernaut or session-tool subcommands are provided here. A zero-match output does not prove error-free collection; read parse diagnostics.

## Diff

Diff accepts **two EVTX files/folders**, not previously exported JSON reports. It compares event-type presence and volume, not arbitrary field-by-field record differences. Spikes/drops use a default factor of 3.

```powershell
py -3.12 evtx_tool.py diff .\baseline-logs .\incident-logs --max-threads 1 -o .\difference.json
py -3.12 evtx_tool.py diff .\baseline-logs .\incident-logs --profile "Process Creation and Termination" --spike-factor 3 -o .\difference.html
```

Options are --profile, --output, --format, --spike-factor, --max-threads and --verbose. There is no diff --anchor/--before/--after. Use parse --timeline-anchor for a timeline window.

## Profiles, benchmark and wizard

```powershell
py -3.12 evtx_tool.py profiles list
py -3.12 evtx_tool.py profiles show "Process Creation and Termination"
py -3.12 evtx_tool.py benchmark .\logs --threads 1
py -3.12 evtx_tool.py interactive .\logs
```

Profiles has list, show, create, delete, export, export-all and import subcommands. Use each subcommand's --help before modifying your profile store. There is no profiles validate command. Benchmark repeats parsing for each --threads value supplied. Interactive is a prompted parse wizard, not a command REPL; see [TUI](13-tui.md).
