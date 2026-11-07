# Sentinel analysis and reporting

Load/build a baseline, then choose target files or a folder in the **Analysis** tab and click **Run Analysis**. Inspect **Results** and **Metrics**. This is a separate input selection from the main grid's visible rows.

```powershell
py -3.12 -m sentinel.cli analyze --help
py -3.12 -m sentinel.cli analyze --evtx .\incident-logs --baseline .\baseline-artifacts --report .\sentinel-report.json
```

CLI analyze accepts one folder or explicit file paths after --evtx. --baseline is the artifact directory, not a pickle filename. Optional --sigma selects a rules directory. Without --report it still prints a summary; there is no --summary or --min-tier option.

## Scores

The engine processes recognized telemetry in timestamp order, tracks lineage per host, and scores process creations. Signals include normalized command/lineage rarity, ancestry mismatch, supported parent-ID inconsistencies, host drift and available image-hash differences. Missing fields cannot establish a negative result for a signal they do not support.

Tier boundaries come from baseline calibration plus scoring adjustments. Read the report's boundaries rather than assuming fixed global cutoffs. Tier 1 suppression/low score is not a guarantee of benign behavior; tier 4 is not confirmation of compromise. Compare the source event, its surrounding activity and baseline suitability before interpreting an alert.

The analysis summary includes scored counts and tier totals. Those counts need not equal every EVTX record: unrelated event IDs and supporting non-create telemetry are not all scored creations.

## Reports

The GUI **File > Export Report (JSON)** and CLI --report generate structured reporting. Top-level JSON sections are **header**, **critical_alerts**, **edge_cases**, and **metrics**. Alert-focused sections contain tiers 4 and 3; this is not an all-event evidence export. The header/metrics include context such as baseline information, boundaries and input hashes when supplied by the run.

Read justifications as explanations of model signals, not assertions that the inferred attack occurred. Retain original EVTX and baseline artifacts to reproduce an investigation. A successful report write does not establish that the baseline was clean or the collection complete.

See [baseline artifacts](16-sentinel-baseline.md) and [Sigma limitations](18-sentinel-sigma.md).
