# Archive: time-window pivots and host identity design

This is a historical design summary dated 2026-10-23, not a current implementation recipe, test result or release guarantee. Earlier machine-specific examples, corpus paths, proposed timing targets and implementation instructions have been removed. Current operation is described in [Around and computer normalization](../../09c-around-this-event.md).

## Design intent retained

An investigator should be able to expand from an event to nearby activity without losing its computer/time context. A new tab should retain an explicit base scope and distinguish a raw-scope expansion from a snapshot of the filtered view. Missing timestamp/computer evidence must not be replaced by a plausible invented value.

Computer identity should distinguish recorded names from grouping. Case, trailing-dot and short/FQDN variants can be normalized, while proposed cross-file links need review. Rename evidence needs provider/field checks; arbitrary unrelated records with the same numeric Event ID are insufficient. A link is an analytical interpretation, not permission to rewrite the recorded computer field.

## Current contracts to consult

- [Around](../../09c-around-this-event.md): window and scope selection, normalized identity and evidence pivots.
- [Advanced Filter](../../06-advanced-filter.md): additional restrictions and loaded filter groups.
- [Time zones](../../06b-timezone.md): display-zone boundaries versus retained event times.
- [Missing IDs](../../09b-missing-record-ids.md): active tab's base scope.
- [Exports](../../11-exporting.md): mode/snapshot limitations.

Implementation lives in evtx_tool/core/time_window.py, evtx_tool/core/host_identity.py and GUI pivot handling. Tests include tests/test_time_window.py and tests/test_host_identity.py. The existence of tests is not a claim that they ran on a particular dataset. Consult [testing](../../22-testing.md) for execution and skip interpretation.
