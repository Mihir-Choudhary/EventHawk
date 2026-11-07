# Time zone and precision

The top-level **Time zone** action opens display settings: local time, UTC, a specific IANA time zone, or a custom UTC offset. The initial model setting is local time. Specific zones need an available time-zone database; `tzdata` is included in the source requirements for Windows.

**Precision** offers **Seconds**, **Milliseconds**, and **Microseconds**. Seconds is the initial setting; the GUI can restore a saved precision. Fractional digits are truncated for display, not rounded. Changing display precision does not remove precision from the underlying timestamp.

GUI date/hour column filters and Advanced Filter time boundaries follow the selected display zone. Internally, event times are treated as UTC. For CLI date bounds, convert times to UTC yourself and use the documented UTC forms. CLI date comparisons are whole-second; numeric offsets are not converted, and timeline anchors reject numeric offsets. This differs from the GUI display-zone conversion and the retained-precision Around window.

Session/activity tools label their times as UTC; do not assume every auxiliary table follows the main grid's time zone. System Activity uses the chosen fractional precision while keeping UTC labels. Evidence exports retain event timestamps rather than simply copying the main grid's formatted cells.

A display setting does not repair an incorrect source clock or prove that two machines were synchronized. Read uncertainty notes for boot, sleep and session boundaries.

See [Advanced Filter](06-advanced-filter.md), [Around](09c-around-this-event.md), and [System Activity](10f-system-activity.md).
