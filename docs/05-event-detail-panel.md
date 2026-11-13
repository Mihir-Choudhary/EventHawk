# Event detail and record identities

Select an event row to view its detail. The **Brief / Full** toggle changes how much retained information is shown: Brief shows the header and available description; Full adds retained System and event-specific fields. The button names the view you can switch to. Full detail is the initial view.

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
