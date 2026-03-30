# GUI Overview

## What It Is

The EventHawk desktop GUI is a PySide6 (Qt6) application with a three-panel layout designed for DFIR workflows. Everything from file selection to threat analysis happens inside this single window.

<img src="screenshots/main_window.png" alt="EventHawk main window — full 3-panel layout with events loaded"/>

---

## Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  Menu Bar:  File  View  Analysis  Help                          │
├──────────────┬──────────────────────────────────────────────────┤
│              │  Toolbar: [Parse] [Filter] [Clear All] [Export]  │
│  LEFT PANEL  ├──────────────────────────────────────────────────┤
│              │                                                   │
│  • Files /   │  EVENTS TABLE                                    │
│    Folders   │  EID | Level | Timestamp | Computer | Provider   │
│              │  … rows …                                        │
│  • Profile   │                                                   │
│    selector  ├──────────────────────────────────────────────────┤
│              │                                                   │
│  • Analysis  │  EVENT DETAIL PANEL                              │
│    options   │  (Brief / XML view of selected event)            │
│              │                                                   │
│  • Stats     ├──────────────────────────────────────────────────┤
│              │  ANALYSIS TABS                                    │
│              │  [ATT&CK] [IOCs] [Chains] [Case]                │
└──────────────┴──────────────────────────────────────────────────┘
│  Status bar: N events | N filtered | Parse time | Mode         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Panel Descriptions

### Left Panel

| Section | Purpose |
|---|---|
| **Files / Folders** | Add individual `.evtx` files or entire folders. Supports drag-and-drop. |
| **Profile selector** | Choose a DFIR profile to pre-filter events. Default: "All Events". |
| **Juggernaut Mode** | Checkbox — enables the columnar high-volume engine for 2M+ events. |
| **Analysis options** | Checkboxes for ATT&CK mapping, IOC extraction, correlation, Hayabusa. |
| **Hayabusa path** | Browse button to set the Hayabusa executable path. |
| **Statistics** | Live counters: total events, filtered count, parse duration. |

### Events Table (Centre Top)

The main table showing all parsed (and optionally filtered) events. Columns:

| Column | Content |
|---|---|
| EID | Windows Event ID |
| Level | Critical / Error / Warning / Information / Verbose |
| Timestamp | UTC timestamp (timezone adjustable) |
| Computer | Source hostname |
| Provider | Event provider (e.g. Microsoft-Windows-Security-Auditing) |
| User | Subject or target user SID / name |
| Channel | Log channel (Security, System, Application…) |
| Source File | Which `.evtx` file this event came from |

Click any column header to sort. Right-click a column header for the [Column Filter Popup](08-column-filters.md).

### Event Detail Panel (Centre Middle)

Shows the full content of whichever row is selected in the events table. Two view modes: **Brief** and **XML**. See [Event Detail Panel](05-event-detail-panel.md).

### Analysis Tabs (Centre Bottom)

Populated after parsing. Contains threat intelligence derived from the full event set. See [Analysis Tabs](09-analysis-tabs.md).

### Status Bar (Bottom)

Shows: total events loaded · events matching current filter · parse duration · active mode (Normal / Juggernaut).

---

## Launching the GUI

```bat
REM Double-click
EventHawk.exe

REM From source
py -3 evtx_tool.py gui
```

---

## Limitations

- The window layout is fixed — panels are not independently detachable.
- Column order is not currently user-rearrangeable via drag.
- Dark theme only in this version; light theme is on the roadmap.

---

## Related Docs

- [Normal Mode](03-normal-mode.md)
- [Juggernaut Mode](04-juggernaut-mode.md)
- [Event Detail Panel](05-event-detail-panel.md)
- [Advanced Filter](06-advanced-filter.md)
- [Analysis Tabs](09-analysis-tabs.md)
