# Around this event and computer normalization

Right-click an event and choose the Around action to open an investigation tab centered on its timestamp and normalized computer identity. Choose a preset or custom before/after window. Time bounds are inclusive and use retained timestamp precision.

When the source table is filtered, the GUI asks whether to draw from the raw base scope or filtered view. A filtered snapshot can intentionally omit records. The tab retains its base scope; clearing ordinary filters does not expand it to the entire collection. Events without usable timestamps cannot be placed in a time window.

## Computer identity

**Tools > Computer Normalisation** groups name variants and supporting evidence. Normalization handles case, trailing dots, short/FQDN forms and supported rename records. An IP is treated as an address, not shortened like a domain name. A missing name remains unknown/blank.

Suggested cross-file links require review before confirmation. Co-occurrence or time proximity alone does not prove that two names represent one machine. Grouping does not rewrite the original event's computer field; preserve that recorded value in evidence.

## Activity pivots

[System Activity](10f-system-activity.md) opens Around tabs at a displayed boundary or moment. That boundary determines the center; the evidence record remains an anchor even when its write time differs.

Juggernaut can browse Around tabs, but an Around snapshot originating from a chain has an explicitly unsupported export path. A notice is not an export receipt.

See [filters](06-advanced-filter.md), [missing IDs](09b-missing-record-ids.md), and [exports](11-exporting.md).
