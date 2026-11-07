# Archive: time-window pivot and host-identity implementation plan

This historical plan is retained as a design summary, not an instruction to execute old edits or an assertion that unchecked tasks passed. The former developer-machine paths, corpus identifiers, benchmark targets and agent-specific execution directives are not current user documentation.

## Original sequence

1. Define a shared time-window representation and normalized host identity.
2. Add an event-centered GUI pivot with explicit time and source-scope selection.
3. Preserve a tab's fixed base scope while allowing ordinary view filters.
4. Expose identity variants and proposed links for analyst review.
5. Exercise boundaries, missing values, multiple source files and both storage modes.

## Review contracts

Use source identity with record identity; a record number alone does not distinguish files. Use inclusive retained-precision time boundaries. Do not convert an ambiguous link into a confirmed identity silently. Keep raw recorded fields available. Confirm that exports and missing-ID analysis operate on the advertised tab scope, including Around/chain tabs.

The current [Around guide](../../09c-around-this-event.md), [filter guide](../../06-advanced-filter.md) and [export guide](../../11-exporting.md) supersede old proposed interfaces. Shared time/identity code is under evtx_tool/core/time_window.py and evtx_tool/core/host_identity.py; GUI integration is in evtx_tool/gui/main_window.py. Relevant tests include tests/test_time_window.py and tests/test_host_identity.py.

No historical corpus timing or correctness result is asserted here. See [testing](../../22-testing.md) for independent output verification and optional real-input checks.
