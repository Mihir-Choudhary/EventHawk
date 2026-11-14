# Event detail and record identities

Select an event row to view its detail. The detail takes the larger share of the bottom area; **Analysis** in its header (also **View > Analysis Panel**, Ctrl+Shift+A) hides the ATT&CK / IOCs / Chains / Bookmarks tabs so the detail takes the whole width, and brings them back. Both choices are remembered. Both views start with the header and, where available, a plain-language description of the event. The **Full | Brief** switch in the panel header shows which view is on: **Brief** stops there; **Full** (the initial view) adds the retained System and event-specific fields.

Descriptions are generated for supported event/provider combinations. They are explanatory text, not the original Windows message-DLL rendering, and a description is not evidence that a rule matched.

## Two different IDs

| Display | Parsed key | Meaning |
|---|---|---|
| Record Number | `record_id` | Number in the binary EVTX record header |
| Event Record ID | `event_record_id` | XML `System.EventRecordID` value, when present |
| Event ID | `event_id` | The event type, not a unique record identity |

The two record IDs can differ. A source file plus record number identifies a retained row more precisely than a record number alone. Copies of logs require additional care when counting unique evidence.

Juggernaut uses the selected row's source/record identity to retrieve detail from Parquet. Missing fields remain missing; they are not reconstructed from the event type. Loading detail can require disk I/O.

## XML and original evidence

The parser keeps values, not the original XML text. The detail display and XML export cannot preserve all original namespaces, ordering, whitespace or unretained System fields. XML export is a reconstructed representation, not an EVTX replacement. Preserve the original file and use an independent EVTX/XML reader when exact original serialization matters.

Use **View > Timestamp Precision** and **View > Time Zone** to control supported timestamp displays; these settings do not change stored event times. See [time zones](06b-timezone.md), [gap checks](09b-missing-record-ids.md), and [exports](11-exporting.md).
