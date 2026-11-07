# Archive: six browsing features design

This is a historical design summary dated 2026-11-01. It records goals, not a current feature-parity guarantee or test receipt. Current guides supersede obsolete proposed interfaces; local paths, identifying examples, unmeasured performance bars and agent execution instructions have been removed.

## Goals

| Area | Intended result | Current guide |
|---|---|---|
| Date tree | Visible expansion controls and day/hour choices | [Column filters](../../08-column-filters.md) |
| Input | Local file/folder drag and drop with errors surfaced | [GUI](../../02-gui-overview.md) |
| Tabs | Column restrictions attached to each tab | [Column filters](../../08-column-filters.md) |
| Custom columns | Retained field tokens with explicit unsupported-field handling | [Custom columns](../../08-column-filters.md) |
| Text search | Search retained event values and generated description | [Advanced Filter](../../06-advanced-filter.md) |
| Export selection | Searchable source selection and per-file choices where supported | [Exports](../../11-exporting.md) |

## Evidence-related constraints

Selections outside a capped popup list must not disappear silently. Search must distinguish a limited visible list from the full searchable value space. Hour filtering must respect the display zone without altering stored timestamps. Custom columns must not invent unretained System fields or drop nonnumeric values during sorting. Copies and same-basename source files must retain their identities.

The original proposal aimed for broad Normal/Juggernaut parity. Current export behavior differs: Juggernaut offers current-view and file-selection scopes without PDF; some snapshots are explicitly unsupported. Read the current guide instead of inferring behavior from the original goal.

Implementation references: evtx_tool/core/custom_columns.py, evtx_tool/core/filters.py, evtx_tool/gui/main_window.py and the Juggernaut model/workers. [Testing](../../22-testing.md) explains why test-file existence or a successful runner does not alone prove complete real-input coverage.
