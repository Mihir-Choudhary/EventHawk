# Exporting

## What It Is

EventHawk can export the currently loaded (and optionally filtered) events, IOCs, and case notes in multiple formats for reporting, sharing, or ingestion into other tools.

---

## How to Export

1. Apply any filters you want — only the **currently visible** events are exported (not the full dataset if a filter is active).
2. Click **File → Export** in the menu bar.
3. Select the desired format.
4. Choose a save location.

> **Tip:** To export ALL events regardless of filter, click **Clear All Filters** before exporting.

---

## Supported Formats

### JSON

**Best for:** Machine-readable output, further processing in Python/scripts, ingesting into SIEM.

Exports a JSON array of event objects, one per event, with the same fields in the same order in Normal and Juggernaut mode:

```json
[
  {
    "record_id": 12345,
    "event_id": 4624,
    "qualifiers": null,
    "timestamp": "2025-05-10T18:08:16.313420Z",
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "provider_guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
    "computer": "DC01.corp.local",
    "level": 0,
    "level_name": "LogAlways",
    "task": 12544,
    "opcode": 0,
    "keywords": "0x8020000000000000",
    "version": 2,
    "process_id": 632,
    "thread_id": 636,
    "correlation_id": "",
    "user_id": "",
    "event_data": {
      "SubjectUserName": "john",
      "LogonType": 2,
      "IpAddress": "192.168.1.5"
    },
    "source_file": "C:\\Cases\\DC01\\Security.evtx"
  },
  ...
]
```

Timestamps are UTC (ISO 8601, `Z`). After `source_file`, an event carries readable meanings of coded fields where EventHawk knows them, in both modes: `logon_type_desc`, `status_code_desc`, `failure_reason_desc` and similar `*_desc` keys, and `"_normalized": true`. In Normal mode an event also carries `attack_tags` when ATT&CK Mapping ran. In Juggernaut mode an event also carries `event_source_name` (the classic provider's legacy source name), which Normal mode does not capture.

### CSV

**Best for:** Spreadsheet analysis in Excel / LibreOffice Calc.

The same layout in Normal and Juggernaut mode (UTF-8 with BOM, so Excel opens it correctly):

`RecordNumber, EventRecordID, EventID, Timestamp, Channel, Provider, Computer, Level, LevelName, Task, Keywords, UserID, ProcessID, SourceFile, ATT&CK`, then one `ED_<name>` column per EventData field in the exported events, sorted by name (e.g. `ED_SubjectUserName`). `RecordNumber` is the record's number in its file (the record header); `EventRecordID` is the number Windows gave the event (what Event Viewer shows). They differ only in a file saved as part of a larger log.

**Safe to open in a spreadsheet.** Event values come from the logged system and can be written by an attacker. A cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return would be run as a formula by Excel or LibreOffice, so EventHawk writes such a cell with one leading apostrophe (`'`), the spreadsheet's mark for "this is text". The original value is the cell without that first apostrophe. Plain numbers such as `-1` or `+44`, and the lone `-` Windows writes for "no value", cannot be formulas and are written as they are. Commas, quotes and line breaks inside a value stay inside its cell. This applies to every CSV EventHawk writes (events, Wi-Fi, Remote Assistance, logon sessions, IOCs). JSON, XML and HTML exports keep every value exactly; the PowerShell `ps_timeline.xlsx` stores such values as text, exactly.

**Very large mixed exports:** when *rows × distinct EventData field names* exceeds 50 million, the `ED_` columns are replaced by one `EventData` column holding each event's EventData as JSON (`{}` when it has none). Otherwise such a file is mostly empty cells: 1.7 million mixed events with ~2,850 field names gave 5.2 GB per-field against 0.9 GB with one `EventData` column. A whole machine's Security and System logs (a few thousand events, a few hundred field names) stay per-field. The same rule applies in both modes, so the same events always give the same file.

`Timestamp` is UTC (ISO 8601, `Z`). `SourceFile` is the full path, since logs collected from several machines are usually all named `Security.evtx`. `ATT&CK` is empty in Juggernaut mode, where ATT&CK mapping is not available.

> **Note:** Not all event_data fields are the same across different event IDs. Sparse columns are expected in a mixed-event-type CSV.

### XML

**Best for:** Windows Event Log compatible format, re-importing into Event Viewer.

Exports events in the standard Windows `.evtxml` format. Each event is a `<Event>` element with `<System>` and `<EventData>` children — identical structure to what Windows uses natively.

### HTML

**Best for:** Shareable self-contained investigation report that opens in any browser.

Exports a single `.html` file with:
- Summary statistics (total events, event ID breakdown, time range)
- Searchable, sortable events table
- Embedded styling — no internet connection required to view

The HTML file is self-contained and can be emailed or shared without any dependencies.

### PDF

**Best for:** Formal investigation reports for management, legal, or legal proceedings.

The PDF report includes:
- Cover page (investigation title, analyst name, date range)
- Executive summary (event counts by category, key findings)
- Timeline section (significant events in chronological order)
- IOC table (every extracted indicator, each value in full)
- ATT&CK matrix summary (techniques detected)
- Case notes section (any events added to the Case tab with annotations)
- Appendix: event table of the first 500 events, labelled "first 500 of N" (the HTML export lists every event)

> **Tip:** Add events to the [Case Tab](09-analysis-tabs.md#case-tab) with notes before exporting PDF to get the most meaningful report.

### STIX 2.1

**Best for:** Threat intelligence sharing with other organisations or security tools that support the STIX standard.

Exports all extracted IOCs as a [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) bundle. IOC types map to STIX objects:

| EventHawk IOC type | STIX Object |
|---|---|
| IP address | `ipv4-addr` |
| Domain | `domain-name` |
| File hash | `file` with hashes |
| File path | `file` with name/path |
| URL | `url` |
| User account | `user-account` |

### OpenIOC

**Best for:** Sharing IOCs with tools that use the Mandiant OpenIOC format (e.g. Redline, GRR Rapid Response).

Exports all extracted IOCs as an OpenIOC XML document with appropriate indicator terms for each IOC type.

### YARA

**Best for:** Generating detection rules from observed IOCs for use with YARA scanners on disk images or memory dumps.

Exports a `.yar` file containing rules generated from:
- File hashes (MD5/SHA1/SHA256) — `hash` condition
- File paths and names — `strings` condition
- Command-line patterns — `strings` condition

---

## Limitations

- Export applies to the **current filter state** — if you want all events, clear filters first.
- Very large exports (6M+ events to JSON or CSV) may take 30–60 seconds and produce large files (JSON: ~1–2 GB for 6M events). For large datasets, export with filters applied.
- PDF generation requires the `reportlab` Python package. If missing, run `pip install reportlab`.
- STIX export requires the IOC Extraction analysis module to have run during parsing. If "IOC Extraction" was not ticked, the STIX export will be empty.
- YARA rules are generated from observed patterns — they are a starting point for rule authoring, not production-ready detections. Review and test before deploying.
- HTML export embeds all event data inline. Files with 500K+ events will produce very large HTML files (~500 MB+) that may be slow to open in browsers.

---

## Related Docs

- [Analysis Tabs — IOCs](09-analysis-tabs.md#iocs-tab)
- [Analysis Tabs — Case Tab](09-analysis-tabs.md#case-tab)
- [CLI Mode — Export options](12-cli.md)
