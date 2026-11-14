# Advanced Filter

Open **Filter** above the event grid. The dialog has five sections, most used first: **Find** (Event ID expressions and text anywhere in the event), **Levels** (with All / None), **Source, channel, user, computer**, **Time**, and **Field conditions**. **OK** applies it; **Cancel** discards the dialog changes. **Clear**, **Load...**, and **Save...** manage the filter configuration.

Event ID expressions accept IDs and ranges; the dialog supports exclusions as well. Values in an ordinary multi-value field are alternatives; restrictions in different fields combine. Excluded values reject matching events. Equal-to conditions on the same field are alternatives (OR); the resulting groups and other conditions combine with AND. There is no separate logical-expression composer in this dialog.

The dialog has one text entry, RegExp and Exclude controls, plus case sensitivity. The toolbar search box edits the same text entry: a term typed there (then **Enter**) shows in the dialog and the other way round; emptying it removes only the text criterion, or the whole Advanced Filter when the search was its only criterion. The CLI/filter backend also supports lists of terms with AND, OR and NOT; those are not extra mode buttons in this dialog. The searchable representation includes retained System values, event data and generated description text. It is not a search of the original EVTX bytes or original XML formatting. Regex capabilities can differ between the Python and DuckDB paths; heed errors from the selected engine.

## Time boundaries

In **Time**, pick one way: a range (**Use dates** compares calendar dates, **Use times** times of day; both together are one continuous range, or with **Times apply to every day** the dates From to To and, on each of those days, only the hours between the two times), **Or the last** days and hours, or **Or one day**. GUI date/time boundaries use the selected display time zone and are converted to UTC for filtering. Stored event times are not rewritten. With relative time enabled the filter evaluates a moving time range rather than a fixed historical case window. See [time zones](06b-timezone.md).

## Load/Save and hidden restrictions

A CLI-saved filter may contain restrictions with no editable dialog field: `profile_groups`, `profile_groups_also`, `event_ids`, `exclude_event_ids`, and `task_categories`. The dialog preserves these on Load, shows an explanatory line, and carries them through Save/OK. **Clear removes them**. A JSON null list does not itself invalidate a CLI-saved filter.

**CLI text searches:** CLI --search stores a list of terms with a mode. Loading such a file puts a single term in the text field; several terms (or NOT) are kept as a restriction named under the dialog's fields, saved again by Save, replaced when you type a text search, and removed by Clear.

Applied GUI profiles and restrictions from a loaded filter intersect. Applying another profile must not widen a loaded file's existing profile constraints. See [profile matching](14-profiles.md).

## Scope

Advanced Filter combines with the current dataset/view, quick filters, column filters and tool-specific restrictions. A file tab or Around tab also has a base scope. Removing ordinary filter layers does not erase that fixed scope. Check the active tab and the result count before exporting or interpreting zero matches.

Saved filters are JSON configuration files, not evidence exports. To save a CLI filter:

```powershell
py -3.12 evtx_tool.py parse .\logs --event-id 4688 --save-filter .\process-filter.json --no-tui -o .\processes.json
py -3.12 evtx_tool.py parse .\logs --filter-file .\process-filter.json --no-tui -o .\reloaded.json
```
