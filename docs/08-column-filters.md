# Column filters and custom columns

Click a supported header to open its value popup. Use the checkboxes, **All**, **None**, search, and **OK**; **Cancel** leaves the selection unchanged. Right-click a header for sorting and column management. Not every built-in header has a value popup.

Column filters belong to the event tab. Switching tabs changes which column restrictions apply. Popup values reflect the tab's scope and other active restrictions; the popup excludes its own column predicate when gathering candidate values.

## Long value lists

Ordinary value lists initially show the most frequent 1,000 values. The popup explains when the initial list is limited. Search can query beyond that initial list; its display has a separate 5,000-value limit and a notice when limited. A value absent from the initial list is not proof that it is absent from the data.

The timestamp tree groups by year, month, day and hour in the display time zone. Days/hours are loaded through the date-specific path rather than the ordinary top-value limit. Partial day selections apply hour restrictions. Selecting all currently shown search results is not the same as clearing the entire column restriction. Selections outside the visible subset are retained rather than silently widening the filter.

## Built-in columns

Right-click a header and choose **Add / Remove Columns**. The dialog supports selecting and ordering visible built-in columns and restoring defaults. Record Number and Event Record ID are separate columns; see [their meanings](05-event-detail-panel.md).

## Custom columns

Choose **Add Custom Column** in the header menu or in an event's right-click menu (that event's fields are then listed to pick from: its own data fields first, filterable by name or value). While you edit, a preview line shows the column's value for that event, or why it would be empty or is not valid yet; **This event (ID)** limits the column to the event's ID. An event type's fields can vary from one event to the next (Restart Manager lists File_1 … File_n; some Defender scans add Scan Trigger), so the list also shows, dimmed, the fields other events with the same provider and ID carry but the selected one does not, with an example value (up to 2,000 such events are read). To show several fields in one column, click them one after another: each is joined to the previous one with the **Join fields with** separator (space, `\` for DOMAIN\user, ` | `, ` / `, `:`, `, `, an arrow, or nothing). Each field shows as a chip under the Value; its × removes it with its separator. Changing the separator re-joins fields that are joined only by separators; hand-written text is left as written. A definition combines literal text with retained field tokens, for example:

```text
{EventID}
{Provider[Name]}
{Data[TargetUserName]}
{Data[3]}
{UserData[Name]}
```

Named Data lookup also searches nested retained event data. Positional Data tokens count from **1**. UserData is an alias for the same field lookup. `{{` and `}}` produce literal braces; a backslash remains a backslash. A stored System field missing from an individual event produces an empty value; an unsupported System token is refused when defined.

Choose text/integer sorting to match the intended column. Non-numeric text is retained rather than coerced into a fabricated number. Custom columns are evaluated for the tab's scope in both modes. The main table's custom columns carry over to the next parse and are computed on the new events (clearing the file list forgets them). CSV/JSON/XML/HTML event exports can carry the selected custom-column values; do not assume that PDF adds the same custom grid columns.

See [Advanced Filter](06-advanced-filter.md) and [exporting](11-exporting.md).
