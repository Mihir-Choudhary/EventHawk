# Accessibility

EventHawk aims at **WCAG 2.2 level AA** for the desktop window, its dialogs and the System Activity HTML report. `tests/test_wcag.py` checks the points below on every run; the theme colours are tested as numbers, not by eye.

## Desktop window and dialogs

| WCAG | What EventHawk does |
|---|---|
| 1.4.3 Contrast | Every text colour reaches **4.5:1** on every background it is drawn on, in Light and Dark: normal, dim and muted text, level and ATT&CK tactic colours, the amber accent. Selected rows use the normal text colour. Text on an amber fill (OK buttons, badges) is near-white in Light and near-black in Dark. Selected text in boxes uses the tan highlight with normal text. |
| 1.4.11 Non-text contrast | Text boxes, combo boxes, spin boxes and checkbox outlines reach **3:1** against the window. Decorative separator lines stay soft. |
| 2.4.7 Focus visible | Keyboard focus is a 2 px amber ring on boxes, combos, spin boxes and checkboxes (plus a tint behind a focused checkbox), and an amber border on buttons. |
| 4.1.2 Name, role, value | Every control has a name a screen reader can say. Icon-only buttons (sidebar, refresh, close tab, the "…" browse buttons, the clear × in search boxes) take it from their tooltip; boxes without a label from their placeholder; the Filter dialog's date and number boxes are named (From, To, Last days, Last hours, One day). |
| 1.4.1 Use of colour | Levels, states and scores are also written as text (Level column, Activity, legends). |
| 2.1.1 Keyboard | Menus, shortcuts (**Help > Keyboard Shortcuts**, Ctrl+/), tables, dialogs and the Full | Brief switch work from the keyboard. |

## System Activity HTML report

| WCAG | What the report does |
|---|---|
| 1.4.3 / 1.4.11 | Text tokens reach 4.5:1 on every surface, input outlines and the focus ring 3:1, in Light and Dark. |
| 2.5.8 Target size | Calendar days are 24 × 24 px; buttons and chips are 28 px or taller. |
| 1.3.1 / 4.1.2 | Tables are ARIA grids (rows, cells, row positions, row count, selected row). The range strip is a slider with its value announced; heatmap cells and calendar days are labelled; every input is labelled. |
| 2.1.1 Keyboard | The range strip moves with the arrow keys; table rows with arrows, Page Up/Down, Home/End and Enter; **/** jumps to the nearest search box; Escape closes the details panel. The day-by-day graphic has a keyboard equivalent: the Periods table lists the same periods. |
| 2.4.1 Bypass blocks | A "Skip to the report" link appears on the first Tab. |
| 2.3.3 / motion | Animations stop under the system's reduced-motion setting. |

## Limits

- The checks are automated (contrast arithmetic, widget and markup inspection). They have not been repeated by hand with each screen reader (NVDA, Narrator, JAWS); Qt's accessibility support depends on the platform bridge.
- The day-by-day timeline and the heatmaps are graphics. Their content is available as text: the Periods table, tooltips and labels.
