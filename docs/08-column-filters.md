# Column filters and custom columns

Click a supported header to open its value popup. Use the checkboxes, **All**, **None**, search, and **OK**; **Cancel** leaves the selection unchanged. Right-click a header for sorting and column management. Not every built-in header has a value popup.

Column filters belong to the event tab. Switching tabs changes which column restrictions apply. Popup values reflect the tab's scope and other active restrictions; the popup excludes its own column predicate when gathering candidate values.

## Long value lists

Ordinary value lists initially show the most frequent 1,000 values. The popup explains when the initial list is limited. Search can query beyond that initial list; its display has a separate 5,000-value limit and a notice when limited. A value absent from the initial list is not proof that it is absent from the data.

The timestamp tree groups by year, month, day and hour in the display time zone. Days/hours are loaded through the date-specific path rather than the ordinary top-value limit. Partial day selections apply hour restrictions. Selecting all currently shown search results is not the same as clearing the entire column restriction. Selections outside the visible subset are retained rather than silently widening the filter.

## Built-in columns

Right-click a header and choose **Add / Remove Columns**. The dialog supports selecting and ordering visible built-in columns and restoring defaults. Record Number and Event Record ID are separate columns; see [their meanings](05-event-detail-panel.md).

## Custom columns

Choose **Add Custom Column** in the header menu. A definition combines literal text with retained field tokens, for example:

```text
{EventID}
{Provider[Name]}
{Data[TargetUserName]}
{Data[3]}
{UserData[Name]}
```

Named Data lookup also searches nested retained event data. Positional Data tokens count from **1**. UserData is an alias for the same field lookup. `{{` and `}}` produce literal braces; a backslash remains a backslash. A stored System field missing from an individual event produces an empty value; an unsupported System token is refused when defined.

Choose text/integer sorting to match the intended column. Non-numeric text is retained rather than coerced into a fabricated number. Custom columns are evaluated for the tab's scope in both modes. CSV/JSON/XML/HTML event exports can carry the selected custom-column values; do not assume that PDF adds the same custom grid columns.

See [Advanced Filter](06-advanced-filter.md) and [exporting](11-exporting.md).
