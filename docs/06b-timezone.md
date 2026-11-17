# Time zone and precision

**View > Time Zone** opens display settings: local time, UTC, a specific IANA time zone, or a custom UTC offset. The initial model setting is local time. Specific zones need an available time-zone database; `tzdata` is included in the source requirements for Windows.

**View > Timestamp Precision** offers **Seconds**, **Milliseconds**, and **Microseconds**. Seconds is the initial setting; the GUI can restore a saved precision. Fractional digits are truncated for display, not rounded. Changing display precision does not remove precision from the underlying timestamp.

GUI date/hour column filters and Advanced Filter time boundaries follow the selected display zone. Internally, event times are treated as UTC. CLI date bounds (`--date-from`, `--date-to`) and `--timeline-anchor` take ISO 8601 times: a `Z` or a numeric offset such as `+02:00` is converted to UTC, and a time without either is read as UTC. CLI date bounds are whole seconds; a bound with a fraction of a second is refused rather than cut. This differs from the GUI, which reads its boundaries in the display zone, and from the retained-precision Around window.

Session/activity tools label their times as UTC; do not assume every auxiliary table follows the main grid's time zone. System Activity uses the chosen fractional precision while keeping UTC labels. Evidence exports retain event timestamps rather than simply copying the main grid's formatted cells.

A display setting does not repair an incorrect source clock or prove that two machines were synchronized. Read uncertainty notes for boot, sleep and session boundaries.

See [Advanced Filter](06-advanced-filter.md), [Around](09c-around-this-event.md), and [System Activity](10f-system-activity.md).
