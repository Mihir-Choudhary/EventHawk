# Exporting

Event export, IOC export, session-tool export and PowerShell extraction are different operations. Check the active tab, selected scope, filters and analysis scope before exporting. Keep original EVTX files: exports are derived representations.

## Event formats and scope

| Path | Formats | Scope |
|---|---|---|
| Normal GUI | CSV, JSON, XML, HTML, PDF | Scope picker: current view, combined files or selected/per-file outputs as offered |
| Juggernaut GUI | CSV, JSON, XML, HTML | Current view, combined, per-file or selected files; no PDF |
| CLI parse | CSV, JSON, XML, HTML, PDF | Matched output, further limited if --limit is used |

Use **File > Export Events** or **Export Report**. Both modes' scope pickers support file search and combined/per-file choices. Current view uses that view's restrictions; combined and selected-file scopes can include events hidden by ordinary view filters. Per-file outputs use distinct names when source basenames collide. Views can have different restrictions: changing scope does not guarantee the same filter set or analysis totals.

Juggernaut current-view export from a chain tab or an Around snapshot originating from a chain is explicitly unsupported. A notice is not a successful receipt. Read the row count/errors and inspect the created file.

```powershell
py -3.12 evtx_tool.py parse .\logs --no-tui -o .\events.csv
py -3.12 evtx_tool.py parse .\logs --no-tui -o .\events.json
py -3.12 evtx_tool.py parse .\logs --no-tui -o .\events.xml
py -3.12 evtx_tool.py parse .\logs --no-tui --ioc --correlate -o .\report.html
py -3.12 evtx_tool.py parse .\logs --no-tui --ioc --correlate -o .\report.pdf
```

Extensions select format; `--format` overrides it. Parent folders must exist. Names here are placeholders.

Juggernaut CSV/JSON has no export row cap. HTML/XML above **100,000** matched events prompts to export the first 100,000 or cancel. Choosing that option produces a partial export; use CSV/JSON for the full scope.

## Data and identity

`record_id` is the EVTX record-header number; `event_record_id` is XML System.EventRecordID. Both are retained where available. Preserve `source_file` to relate rows to originals. Missing values differ from proved zero. Normal/Juggernaut exports need not have byte-identical serialization or enrichment.

CSV is tabular; JSON retains structured event data. XML reconstructs an event representation, not original bytes or an EVTX replacement. CSV/JSON/XML/HTML can include custom-column output; PDF has its own layout.

### Formula-safe spreadsheets

CSV text starting with `=`, `+`, `-`, `@`, TAB or CR receives one leading apostrophe. Plain numeric values and the lone `-` remain unchanged. CSV cell text can intentionally differ from the raw value. PowerShell XLSX likewise writes text as text, not formulas.

### HTML and PDF

HTML includes its report data for local viewing. Large scopes can make large files and slow browsers; there is no fixed size/render-time guarantee.

PDF includes summaries/analysis and an event-table preview limited to **500 events**. The cover's **Total Events** is the number supplied to the exporter, not a separate full-collection count. **Chains Found** is 0 when correlation ran with no chains, and **n/a** when it was not run for that export scope. **IOCs Found** counts list entries across supplied categories; it is n/a when extraction was not supplied. Current-view/selected-file exports do not reuse full-collection IOC/chain totals. Missing IOC/correlation analysis is not evidence of no IOCs/chains. PDF is not a case-note or annotation system.

## IOC exports

Use **Export IOCs** after extraction. These export extracted categories, not all event rows.

| Format | Behavior and limits |
|---|---|
| CSV / bulk text | Type/value information for review or downstream preparation |
| STIX JSON | Bundle of indicators with patterns and millisecond UTC creation times; supports addresses, domains, URLs, hashes, users, filepaths, registry, commandlines, processes and DLLs. Computers, named pipes, services, tasks and shares are unrepresented; the GUI reports omissions and points to CSV/bulk text. |
| MISP JSON | Event/attribute structure using the exporter's category/type map and epoch-second attribute timestamps. Computers and DLLs have no mapping in this path. |
| YARA | Rule skeleton using hashes and selected domains, URLs, commands and processes; not an exhaustive IOC export. |

STIX pattern strings escape backslashes and quotes. These representations do not guarantee acceptance of every value by every consumer. Validate in the intended downstream tool before operational use.

YARA uses at most 100 domains and 100 URL candidates (excluding URLs longer than 200 characters), plus 50 commandlines scoring above 50 and 50 processes scoring above 60. Command/process strings are shortened to 60/80 characters. A string family is referenced only when defined; control characters are escaped. The rule imports YARA's hash module. Review/compile the skeleton with your YARA version; it is not a complete detection rule set.

Session/activity browsers export shown rows with their own scope and notes. [PowerShell extraction](10b-ps-extract.md) has separate artifacts and coverage information.
