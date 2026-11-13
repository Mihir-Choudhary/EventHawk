# Normal mode

Normal mode keeps parsed event dictionaries in application memory. Choose it when the collection and requested analysis fit the available RAM. There is no documented record-count boundary that guarantees a collection will fit.

1. Add `.evtx` files or directories with **Add files** / **Add folder**.
2. Choose the analysis checkboxes and click **Parse**. Small loads take the Normal path. For a load that triggers the volume warning, **Proceed Anyway** selects Normal mode; inspect the warning before accepting that risk.
3. Wait for completion and read parse warnings. Parsed events populate the grid; a progress count is not a promise that partial results are already available for browsing.
4. Select rows for detail, or use profiles and filters to narrow the loaded collection.

GUI profiles are view filters applied with **Apply**. They do not avoid parsing the other events in the queued files. CLI `parse --profile` has different, parse-result filtering behavior.

A new parse replaces the previous result and invalidates dataset-specific views and analysis state. Export material you need before replacing it. The square **Stop** button beside Parse requests cancellation; wait for the application to finish cleanup before starting another parse or closing it.

Memory depends on event count, field sizes, derived descriptions, filters and analysis results. Worker settings and CPU/RAM controls do not establish a hard maximum for the entire GUI process. [Juggernaut](04-juggernaut-mode.md) changes the storage layout but still uses RAM.

See [filters](06-advanced-filter.md), [profiles](14-profiles.md), and [performance](19-performance.md).
