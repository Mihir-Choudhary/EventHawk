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

Exports a JSON array of event objects. Each object contains all parsed fields:

```json
[
  {
    "record_id": 12345,
    "event_id": 4624,
    "level": "Information",
    "timestamp_utc": "2025-05-10T18:08:16.313420Z",
    "computer": "DC01.corp.local",
    "provider": "Microsoft-Windows-Security-Auditing",
    "channel": "Security",
    "user_id": "S-1-5-18",
    "event_data": {
      "SubjectUserName": "john",
      "LogonType": "2",
      "IpAddress": "192.168.1.5"
    }
  },
  ...
]
```

### CSV

**Best for:** Spreadsheet analysis in Excel / LibreOffice Calc.

Exports a flat CSV with one column per parsed field. `event_data` fields are flattened with dot notation (e.g. `event_data.SubjectUserName`). Timestamps are in ISO 8601 format.

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
- IOC table (all extracted indicators with scores)
- ATT&CK matrix summary (techniques detected)
- Case notes section (any events added to the Case tab with annotations)
- Appendix: raw event table

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
