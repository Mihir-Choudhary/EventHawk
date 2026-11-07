# Performance and capacity

No fixed throughput, maximum event count, memory ceiling, or latency guarantee is established for the current product. Collection structure, event payload width, storage, worker count, filters and analysis all affect results. Old benchmark figures are not a sizing guarantee.

## Storage modes

Normal mode retains event dictionaries in memory. Juggernaut writes Zstandard-compressed Parquet and loads selected data into Arrow, using DuckDB for queries. It still retains metadata/search values, and some operations read full records. Neither filtering nor detail is universally disk-free or zero-copy; text conversion, sorting, custom columns and analysis can allocate additional memory.

Session/activity tools can load substantial subsets. In Juggernaut, WiFi/Remote Assistance/System Activity ask before loading more than 200,000 relevant rows. This is a confirmation, not a cap or a promise of a fixed memory footprint. The prompt's estimate is not measured peak RAM. Large Logon Session filtering has a separate 100,000-event confirmation.

## Measure your collection

Run from the repository root with representative local inputs:

```powershell
py -3.12 evtx_tool.py benchmark .\logs --threads 1
py -3.12 evtx_tool.py benchmark .\logs --threads 1 --threads 2
```

Benchmark reparses inputs for each requested count and reports elapsed time, processed records, records/sec and MB/sec. It measures this parse path, not GUI scrolling, Juggernaut, all analysis or export throughput. Compare read errors and record counts as well as speed. Cache effects can make repeated runs differ.

CLI --max-threads controls worker processes despite the option name. More workers need not improve throughput, particularly for a small number of files, slow storage or memory-heavy events. CPU/RAM monitor settings are not a hard cap on whole-application memory.

Keep space for Parquet and exports. STOP requests cancellation; wait for cleanup before replacing a dataset or deleting temporary files. Avoid concurrent Juggernaut GUI sessions using the shared session-temp location.

See [Normal](03-normal-mode.md), [Juggernaut](04-juggernaut-mode.md) and [exports](11-exporting.md).
