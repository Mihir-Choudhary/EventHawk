# Archive: six browsing features implementation plan

This historical plan is a summary of intended work, not an active task list or a test result. It no longer contains developer-machine paths, corpus-derived examples, agent-specific directives or performance targets presented as product guarantees.

## Original implementation areas

1. Date-tree expansion controls, followed by hour selection beneath days.
2. File/folder drag and drop with unmatched/missing paths reported.
3. Column-filter state owned by each event tab and invalidated with that tab.
4. A shared custom-column evaluator for retained System and Data values.
5. Whole-event text search across retained values and descriptions.
6. A searchable export picker with combined/per-file choices where supported.

## Current verification focus

| Concern | Existing regression entry points |
|---|---|
| Date controls/hour boundaries | tests/test_date_tree_chevrons.py, tests/test_date_tree_hours.py |
| Custom values and ordering | tests/test_custom_columns_eval.py, tests/test_custom_column_userdata_order.py |
| Whole-event search | tests/test_search_whole_event.py |
| Search/selection continuity | tests/test_popup_search_apply.py, tests/test_popup_search_sequence.py |
| Export identity and selection | tests/test_export_file_picker.py, tests/test_separate_export_names.py |

These references identify code to inspect/run, not results claimed by this document. A useful test checks produced values against an independent expected result, covers missing fields and excluded/out-of-list values, and inspects warnings and skips. See [testing](../../22-testing.md).

Current [column](../../08-column-filters.md), [filter](../../06-advanced-filter.md) and [export](../../11-exporting.md) guides define user-facing behavior. Do not assume every originally proposed export scope exists in Juggernaut; its formats, scopes and unsupported snapshot cases are documented there.
