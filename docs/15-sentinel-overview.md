# Sentinel Baseline Engine

Sentinel compares process activity with a baseline built from representative logs. It normalizes process/command information, models frequency and ancestry, and scores deviations. A high score is a review priority, not proof of malware; suppression is not proof of safety.

Open **Tools > Baseline Analysis (Sentinel)**. The separate window has **Baseline Setup**, **Analysis**, **Results**, and **Metrics** tabs. Build/load a baseline, choose target inputs, run analysis, then inspect results and export a report. It does not merely analyze the rows currently visible in the main EventHawk grid.

The parser recognizes Security process creation/termination (4688/4689) and supported Sysmon process/relationship records (1/5/8/10). Scoring focuses on process creation. Application/System logs alone do not provide a useful process baseline. Sentinel uses its own parsing/scoring path rather than the main grid's Juggernaut store.

## Interpretation

| Tier | Meaning in the product |
|---|---|
| 1 | Suppress from alert-focused presentation |
| 2 | Aggregate |
| 3 | Highlight / edge case |
| 4 | Critical review priority |

Boundaries are calibrated from baseline scores and adjusted for scoring; they are not universal 20/45/70 cutoffs. The scoring adjustment keeps aggregate/highlight floors of 45/70 while the suppression boundary remains baseline-derived with drift headroom. Results depend on the baseline, configuration, recorded fields and target scope. Missing command lines, lineage or hashes limit the corresponding signals.

The optional Sigma integration is heuristic title-keyword pre-tagging, not full Sigma condition evaluation. Its tags do not automatically remove events from the baseline. See [Sigma limitations](18-sentinel-sigma.md).

See [building a baseline](16-sentinel-baseline.md) and [analysis/reporting](17-sentinel-analysis.md). Earlier screenshots in `screenshots/` are illustrations, not current output verification.
