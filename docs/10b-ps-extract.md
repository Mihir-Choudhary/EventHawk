# PowerShell History

**PowerShell History** is in the **Tools** menu. Queue files/directories first, click the action and choose an output folder. Extraction reads queued EVTX files; it does not require a preceding grid parse or use the grid's current view filter.

The extractor reads Windows PowerShell classic, Microsoft-Windows-PowerShell/Operational and PowerShellCore/Operational channels. Its extracted event-ID set is **300, 400, 403, 600, 800, 4100, 4102, 4103, 4104, 53504**. Other observed PowerShell IDs are counted in the summary.

## Outputs

| Output | Purpose |
|---|---|
| `ps_commands.txt` | Command/session timeline with summaries/previews |
| `scriptblock_<key>.txt` | Reassembled block files |
| `ps_extraction_summary.txt` | Counts, coverage and analysis summary |
| `ps_extraction.json` | Structured extraction with full retained values |
| `ps_timeline.xlsx` | Excel timeline and script-block hyperlinks |

These are five output types, not necessarily five files: many blocks can produce many files. Keys are filename-safe. Keep the workbook beside its block files for relative hyperlinks. Overlong workbook cells are marked with a reference to the full JSON value; text previews likewise are not complete content. Spreadsheet text is written as text rather than formulas.

## Interpretation

Available lifecycle/runspace evidence forms sessions; multipart blocks are reassembled and supported encoded content is decoded. Missing fragments and boundaries limit reconstruction. A failed decode is not proof of harmless content.

Keyword/ATT&CK annotations are hints, not complete detection coverage or proof of execution. Do not execute extracted content during investigation. Coverage depends on what was logged and collected; EventHawk cannot recover an unrecorded script. Review summary counts, missing-fragment information, errors and cancellation before treating extraction as complete.

This is a GUI action, not a `parse --powershell` CLI option. See [analysis](09-analysis-tabs.md).
