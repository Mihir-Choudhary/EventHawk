# Missing record IDs

Show **Record Number** or **Event Record ID** through **Add / Remove Columns**. Right-click the relevant header and choose **Identify Missing Record Numbers** or **Identify Missing Event Record IDs**. These check different record fields, not Event ID.

## Scope

The check uses the active tab's base events, grouped by source file. Ordinary view filters are ignored so they cannot hide gaps. The tab's fixed scope still applies in both modes:

| Active tab | Checked scope |
|---|---|
| All Events | Loaded dataset, grouped by file |
| File | That file's base events |
| Around | That tab's fixed host/time window |
| Chain | That tab's own event dictionaries |

An intentionally narrow Around/chain tab need not contain a contiguous sequence from the original file.

## Interpretation

The check uses observed minimum/maximum and distinct sorted IDs, reporting ranges between adjacent IDs. It does not assume the first retained ID is 1 or establish anything outside the observed range. Duplicate IDs add no further coverage.

A gap means an ID inside that scope's observed range is absent from parsed rows. Partial collection, corrupt/unparsed records and pivot scope affect this result. A gap alone does not prove deletion or tampering. No gap does not prove completeness or integrity.

Use parse warnings and an independent reader of the original file when investigating loss. See [record identities](05-event-detail-panel.md).
