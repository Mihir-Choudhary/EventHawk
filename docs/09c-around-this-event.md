# Around This Event

## What It Is

**Around this event** opens a new tab with every event that happened within a time window around one event: what the machine was doing in the minutes before and after a logon, a service install or a log clear. It works the same in Normal and Juggernaut mode.

---

## How to Open It

Right-click any event in an events table (All Events, a per-file tab, a chain tab, or another around tab) and choose **⏱ Around this event**:

```
⏱ Around this event ▸ On this host (3 names)          ▸ ±1 min | ±5 min | ±15 min | ±1 hour | ±1 day | Custom…
                    ▸ On this host + 1 suggested name ▸ (same)
                    ▸ On all hosts                    ▸ (same)
```

- **On this host** — every Computer name of the clicked event's machine (see [One machine, several names](#one-machine-several-names)). Hover it to see each name and why it is included.
- **On this host + K suggested names** — also the names that are only *suggested* to be the same machine. Shown only when there are suggestions.
- **On all hosts** — every event in the window, whatever machine wrote it.
- **Custom…** — before and after set separately, each a number and a unit (minutes, hours or days), from 0 up to 365 days a side. A window of 0 / 0 shows the events at exactly the clicked event's time.

An event with no readable timestamp has no window around it; the item is greyed out and says so.

---

## The Filter Question

If the table you clicked has any filter on (Advanced, Quick, session, record key, tactic or text), you are asked which events the new tab draws from:

- **Include all loaded events** (default) — the window over everything loaded.
- **Only events that pass the current filters** — a snapshot of exactly what that table shows at that moment.

With no filter on, the two are the same and nothing is asked.

---

## The Window

- The window is **[event time − before, event time + after]**, inclusive at both ends, compared in UTC to the microsecond.
- Times are shown in your [display time zone](06b-timezone.md), using the daylight-saving rule of each event's own date — never today's offset.
- Events with no timestamp cannot be placed in any window. They are left out, and the tab's tooltip says how many.

---

## The Tab

- **Label:** `⏱ <machine> ±<window> <time>`, for example `⏱ DESKTOP-A8CALR3 ±5 min 16:24:25`, or `⏱ All hosts …`. A custom window shows as `-<before>/+<after>`.
- **Tooltip:** the clicked event (time, event ID, host, file, record ID), the exact window start and end with their UTC offsets, the host names included and why, whether it is all loaded events or a filtered snapshot, the number of events, and the number left out for having no timestamp.
- **Selection:** the clicked event's row is selected and scrolled to the middle. If it is not in the tab (a filtered snapshot that excluded it), the nearest event in time is selected and the status bar says so.
- **Everything works as in a per-file tab:** the detail panel, Quick Filters, column filters, sorting, bookmarks, export, and further Around pivots from inside the tab. A Quick Filter applied in an around tab filters only that tab. Global filters applied elsewhere do not change it — its contents are what you asked for.
- Close it with **×** on the tab, or **Close Tab** from the file tree.

---

## One Machine, Several Names

Windows stamps each event with the machine's name *at the moment it was written*, and that name changes:

- **Rename.** The random setup name (for example `WIN-VR474TJ38H3`) is replaced at the end of first setup. Event **6011** in the System log records "the name changed from X to Y".
- **Domain join.** After joining a domain, some components write the full name (`WIN-FPV0DSIC9O6.sigma.fr`) and others the short name (`WIN-FPV0DSIC9O6`).

Of seven public single-machine log collections, six record more than one name. Matching hosts by exact name would silently drop events: on the Windows 10 collection, ±5 minutes around the rename holds 601 events, 255 of them under the setup name.

EventHawk links names by evidence:

| Link | Applied | When |
|---|---|---|
| Rename | automatically | an EID 6011 says one name became the other (chains are followed) |
| Domain suffix | automatically | `X` and `X.<domain>`, when only one domain occurs for `X` |
| Domain suffix, several domains | suggestion | `X.a` and `X.b` both occur — possibly two machines |
| Shared local log file | suggestion | two names in the same local `.evtx` (a ForwardedEvents log holds many machines, so it suggests nothing) |

IP addresses are kept whole (`10.0.0.5` and `10.0.0.6` are different hosts) and blank Computer values are only ever grouped with each other. A 6011 whose names cannot be read is never guessed at; Computer Normalisation counts it.

---

## Computer Normalisation

**Tools → Computer Normalisation…** uses the same grouping: one row per machine, with an **Evidence** column (`rename at <time>`, `domain suffix`, `confirmed: shared file …`, `suggested: shared file …`).

Right-click a row with a suggestion to **Confirm suggested link** (the two names become one machine everywhere, including "On this host") or **Reject suggested link**. Confirmations last until a new dataset is loaded.
