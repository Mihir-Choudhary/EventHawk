# Juggernaut mode

Juggernaut stores parsed events in Zstandard-compressed Parquet shards and loads selected columns into Arrow. DuckDB supplies queries against that data. This reduces the need to retain full event dictionaries for the main grid; metadata, text/search values, sorting, custom columns and tool results still use memory that grows with the collection.

Click **Parse**. When the selected input exceeds the GUI's estimated RAM/responsiveness limits, the **Large Data Volume Detected** prompt offers **Use Juggernaut Mode**, **Proceed Anyway** (Normal), or **Cancel**. Choose **Use Juggernaut Mode** there; there is no separate mode checkbox. After loading, a **Juggernaut** chip beside the event count shows the mode; browse and filter the grid much as in Normal mode. Selecting detail may read the full event from Parquet using its source file and record-header number. Record numbers alone are not unique across files.

## Differences to account for

- This is a GUI mode; there is no CLI `--juggernaut` flag.
- ATT&CK analysis is not available through the Juggernaut analysis path. Do not assume every Normal-mode analysis option has parity here.
- Export offers CSV, JSON, XML and HTML with current-view, combined, per-file and selected-file scopes. PDF is not offered. Current-view export from a chain tab or an Around snapshot originating from a chain is explicitly unsupported; heed the message rather than treating it as a completed export.
- HTML/XML exports above 100,000 rows ask before writing only the first 100,000; CSV/JSON export the full selected scope.
- WiFi History, Remote Assistance Sessions and System Activity first count relevant rows. Above **200,000** rows the GUI asks before loading them into memory. This is a confirmation threshold, not a result cap; choosing No leaves the tool unloaded. The prompt's memory figure is an estimate.
- Applying a large Logon Session filter has a separate confirmation above **100,000** matching events.

Profiles, Advanced Filter, ordinary column filters, and a pivot tab's fixed scope combine. Clearing a column filter does not turn a file or Around tab into the whole dataset.

## Temporary storage

The parse worker uses `evtx_jm_session` under the system temporary directory and replaces stale session contents on a new run. It writes Parquet shards and `parquet_manifest.json`. These files contain event data. Do not delete them while an operation is using them, and avoid simultaneous Juggernaut GUI sessions sharing that temporary location.

Keep free disk space for the shards and exports. Neither disk requirements nor RAM usage have a fixed multiplier guaranteed by the product. Wait for cancellation/close cleanup before reusing files or starting a replacement operation.

See [performance](19-performance.md), [exports](11-exporting.md), and [session tools](10c-logon-sessions.md).
