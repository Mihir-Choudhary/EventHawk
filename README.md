# EventHawk

EventHawk is a Windows EVTX investigation tool with a PySide6 desktop interface and a command-line parser. It combines event browsing, filters, ATT&CK tagging, IOC extraction, correlation, and session tools. Findings are investigative leads: a rule match or a record-number gap alone does not prove an attack.

## Start from source

The commands below use PowerShell from the repository root, Python 3.12, and the current `beta` source. Install dependencies in the environment you intend to use. The source checkout and the two Windows packaging approaches have different runtime requirements; see [installation](docs/01-installation.md).

```powershell
git clone --branch beta https://github.com/Mihir-Choudhary/EventHawk.git
cd EventHawk
py -3.12 -m pip install -r requirements.txt
py -3.12 evtx_tool.py gui
```

For an existing checkout, run the last two commands from its root. Example input/output names throughout these guides are placeholders; replace them with your own files. Do not overwrite evidence with an export.

```powershell
py -3.12 evtx_tool.py parse .\logs --no-tui -o .\events.json
py -3.12 evtx_tool.py parse --help
```

## Investigate

- **Normal mode** retains parsed event dictionaries in memory. **Juggernaut mode** uses Parquet, Arrow and DuckDB for larger collections. Its metadata and analysis loads still consume memory; it is not a constant-memory mode. See [Normal](docs/03-normal-mode.md), [Juggernaut](docs/04-juggernaut-mode.md), and [performance](docs/19-performance.md).
- **32 built-in profiles** select event IDs together with their provider/channel constraints. GUI profiles filter loaded events after **Apply Profiles**; CLI profiles restrict the parse result. See [profiles](docs/14-profiles.md).
- **Advanced Filter**, cell quick filters, per-tab column filters, custom columns, and **Around this event** help narrow or expand an investigation. Loaded filter files retain restrictions that do not have an editable dialog field. See [filtering](docs/06-advanced-filter.md), [columns](docs/08-column-filters.md), and [Around](docs/09c-around-this-event.md).
- **Record Number** is the EVTX record-header number; **Event Record ID** is XML `System.EventRecordID`. They can differ. Gap checks use the active tab's base scope. See [detail](docs/05-event-detail-panel.md) and [missing IDs](docs/09b-missing-record-ids.md).
- **Tools** opens Logon Sessions, WiFi History, Remote Assistance Sessions, System Activity, Computer Normalisation, and Sentinel. **PowerShell History** is a separate top-level action. Durations and activity boundaries carry uncertainty notes. See the guides below.
- **ATT&CK**, **IOCs**, **Chains**, and **Bookmarks** are the analysis tabs. ATT&CK is enabled by default; IOC extraction, correlation and Hayabusa are opt-in. See [analysis](docs/09-analysis-tabs.md) and [Hayabusa](docs/10-hayabusa.md).
- **Event exports** support CSV, JSON, XML, HTML and PDF in Normal mode/CLI; Juggernaut offers CSV, JSON, XML and HTML with its scope picker. IOC exports have separate STIX, MISP and YARA capabilities and limits. CSV applies formula-safe escaping. See [exporting](docs/11-exporting.md).
- **Sentinel** compares process activity with a baseline. Its tiers are priorities for review, not a verdict that an event is safe or malicious. See [Sentinel](docs/15-sentinel-overview.md).

## Guides

| Topic | Guide |
|---|---|
| Setup and interface | [Installation](docs/01-installation.md), [GUI overview](docs/02-gui-overview.md) |
| Event browsing | [Detail panel](docs/05-event-detail-panel.md), [time zones](docs/06b-timezone.md), [quick filters](docs/07-quick-filters.md) |
| Sessions and activity | [PowerShell](docs/10b-ps-extract.md), [logons](docs/10c-logon-sessions.md), [remote sessions](docs/10d-inbound-rdp.md), [downtime](docs/10e-downtime-in-sessions.md), [System Activity](docs/10f-system-activity.md) |
| Terminal | [CLI](docs/12-cli.md), [TUI and wizard](docs/13-tui.md) |
| Baselines | [Build](docs/16-sentinel-baseline.md), [analyze](docs/17-sentinel-analysis.md), [Sigma limitations](docs/18-sentinel-sigma.md) |
| Development | [Thin launcher](docs/20-building-release.md), [standalone build](docs/21-building-standalone.md), [tests](docs/22-testing.md) |

The PNGs in `docs/screenshots/` illustrate earlier UI versions. Current labels and behavior are described in the guides; those images are not evidence of the current version's output.

## Limits and evidence

EventHawk retains parsed values, not the original XML byte stream. XML exports reconstruct an event representation; preserve original EVTX files for evidence. Features that need data absent from the collection cannot recover it. Read errors, coverage notices, omitted export categories and duration notes before drawing conclusions.

There is no fixed throughput, memory ceiling, or latency guarantee. Measure your collection and requested analysis on your own machine. GUI-only session/activity tools have no equivalent CLI subcommand.

Licensed under [Apache License 2.0](LICENSE).
