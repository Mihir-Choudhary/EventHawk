# GUI overview

Launch from the repository root:

```powershell
py -3.12 evtx_tool.py gui
```

The left panel queues files, selects profiles and analysis, and starts parsing. **+ Files** and **+ Dir** add inputs; **PARSE** starts parsing (large loads offer a mode choice) and **STOP** requests cancellation. Local file/folder drag and drop is also supported. Review messages about missing or unmatched inputs.

The event grid begins with **All Events**. File tabs and investigation tabs have their own scope and column filters. The detail pane describes the selected row. The analysis area has **ATT&CK**, **IOCs**, **Chains**, and **Bookmarks** tabs.

## Menus and actions

| Location | Actions |
|---|---|
| File | Add File(s), Add Directory, Export Events, Exit |
| Tools | View Logon Sessions, WiFi History, Remote Assistance Sessions, System Activity, Computer Normalisation, Clear Results, Baseline Analysis (Sentinel) |
| Time zone | Opens timestamp display settings |
| Help | Open Log Folder |
| Precision | Seconds, Milliseconds, Microseconds |
| PowerShell History | Starts extraction from the queued input files after choosing an output folder |

Profiles are in the left panel: select checkboxes, then **Apply Profiles**. **New Profile** and **Edit Profile** open profile editing. Ticking a box alone does not apply the profile.

ATT&CK Mapping starts checked. IOC Extraction, Correlation Engine and Hayabusa Rules start unchecked. Their results depend on the loaded collection. In separate view, the Analysis selector offers This File / All Files for the ATT&CK summary; IOC and chain results retain their analysis-run scope. Ordinary grid filters do not automatically recompute those results.

## Grid and filtering

Click a supported column header for its value filter. Right-click a header for sorting, **Add / Remove Columns**, custom columns, and the two record-ID gap checks on their respective headers. Right-click a cell for quick filters and event actions. **Filter** opens Advanced Filter; **Clear All Filters** clears the filter layers handled by that action. Investigation tabs can also have a fixed base scope that clearing ordinary filters does not expand.

The built-in grid has 23 columns; the initial visible set is the first nine: row number, Event ID, Level, Timestamp, Computer, Channel, User, ATT&CK, and Source File. Add the other columns through the header menu.

The current theme uses a light cream palette. Screenshots under `screenshots/` show earlier UI versions and may differ from the current layout.

See [detail](05-event-detail-panel.md), [columns](08-column-filters.md), [analysis](09-analysis-tabs.md), and [exports](11-exporting.md).
