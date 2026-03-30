# Sentinel — Sigma Rules

## What It Is

Sigma rules are an optional but recommended enhancement for Sentinel. During both the baseline build and the analysis phase, Sentinel can pre-tag every parsed event with MITRE ATT&CK technique IDs matched from the Sigma rule set. These tags:

1. **Improve baseline quality** — Sigma-tagged known-malicious events can be excluded from the frequency model so attacker behaviour does not pollute the baseline.
2. **Enrich analysis output** — Tier 3/4 findings include ATT&CK technique names and IDs in their justification text, making reports more actionable.

Sigma integration is **optional** — Sentinel works without it, but output quality improves with it.

---

## What Sigma Rules Are

[Sigma](https://github.com/SigmaHQ/sigma) is an open, generic signature format for describing detections in SIEM and log analysis tools. The SigmaHQ community maintains thousands of rules covering Windows attack techniques, mapped to MITRE ATT&CK.

Sentinel uses Sigma rules only for pre-tagging (labelling events with technique IDs). It does not use Sigma as a primary detection mechanism — that is Hayabusa's role. See [Hayabusa Integration](10-hayabusa.md).

---

## Step 1 — Download the Sigma Rule Set

Clone the official SigmaHQ repository:

> **https://github.com/SigmaHQ/sigma**

```bat
git clone --depth 1 https://github.com/SigmaHQ/sigma.git C:\sigma
```

`--depth 1` downloads only the latest commit, skipping full git history (~100 MB total instead of ~400 MB).

The rules relevant to EVTX analysis are in:

```
C:\sigma\rules\windows\       ← Windows-specific rules (recommended)
C:\sigma\rules\               ← Full library (includes Linux, cloud, etc.)
```

**For EVTX analysis, point Sentinel at `C:\sigma\rules\windows\`** — this covers process creation, network, authentication, lateral movement, and more, without including rules for non-Windows platforms.

### Keeping Rules Up To Date

```bat
cd C:\sigma
git pull
```

Run this periodically to get new rules. Re-run the baseline build after a major rule update if the set of tagged events changes significantly.

---

## Step 2 — Pass the Path to Sentinel

### CLI — Baseline Build

```bat
python -m sentinel.cli build ^
    --evtx C:\Baseline\Logs ^
    --output C:\SentinelBaseline ^
    --sigma C:\sigma\rules\windows
```

### CLI — Analysis

Use the **same rules directory** that was used during the build:

```bat
python -m sentinel.cli analyze ^
    --evtx C:\Target\Security.evtx ^
    --baseline C:\SentinelBaseline ^
    --sigma C:\sigma\rules\windows ^
    --report report.json
```

> **Important:** Always use the same sigma directory for build and analysis. Using different rule sets between phases can produce inconsistent tagging and inflate false positives.

### GUI

1. In the Sentinel GUI (Baseline tab or Analysis tab), click **Browse** next to the "Sigma rules directory" field.
2. Navigate to `C:\sigma\rules\windows` and click OK.
3. The path is remembered for the session.

---

## How It Works Internally

During parsing, each event is checked against all loaded Sigma rules. Matching rules contribute their ATT&CK technique ID(s) to the event's `attck_tags` set.

**During baseline build:**
- Events tagged with Sigma rules are recorded as "potentially suspicious" in the frequency model metadata.
- The frequency model still includes them (they may be legitimate admin activity that happens to match a broad rule), but their presence is flagged for later analysis comparison.

**During analysis:**
- Tier 3/4 events that also match Sigma rules have the technique ID added to their justification: e.g. `"Matches Sigma rule: T1059.001 — PowerShell"`.
- This gives analysts a second signal source confirming the finding.

---

## Rule Loading Performance

| Rules loaded | Build pre-tagging time | Analysis pre-tagging time |
|---|---|---|
| ~500 (windows/process_creation only) | ~8 s | ~5 s |
| ~2,000 (windows/ full) | ~25 s | ~15 s |
| ~4,000 (rules/ full) | ~55 s | ~30 s |

These times are for 400K events. Pre-tagging runs once and adds a one-time cost to build/analysis startup.

---

## Limitations

- Sigma rules are loaded and evaluated using Sentinel's built-in `SigmaTagger` implementation. This covers the most common Sigma condition types (`keywords`, `selection`, `filter`, `AND/OR/NOT`). Very complex multi-detection Sigma rules with `near` or `temporal` conditions are not supported and are silently skipped.
- Rules that reference event IDs or channels not present in your logs simply never match — no errors are raised.
- A fresh Sigma clone contains ~4,000+ rules. Parsing all of them takes ~55 seconds on first use. Rules are cached in memory for the duration of the process.
- Sigma rules can produce false positive tags on legitimate activity (e.g. a rule for "PowerShell download" that matches any `Invoke-WebRequest` call). This does not cause problems in Sentinel — tagging enriches output but does not change the statistical scoring.
- The `--sigma` path must be a directory containing `.yml` files (recursively searched). Passing a single rule file is not supported.

---

## Alternative: Hayabusa for Sigma Detections

If your goal is **Sigma-based detection** (not baseline anomaly scoring), use [Hayabusa Integration](10-hayabusa.md) with EventHawk instead. Hayabusa runs all ~3,000 Sigma rules with full support for complex conditions and produces richer ATT&CK-mapped detections. Sentinel's Sigma integration is specifically for pre-tagging to enrich anomaly scoring — it is not a replacement for Hayabusa.

---

## Related Docs

- [Sentinel — Overview](15-sentinel-overview.md)
- [Sentinel — Building a Baseline](16-sentinel-baseline.md)
- [Sentinel — Running Analysis](17-sentinel-analysis.md)
- [Hayabusa Integration](10-hayabusa.md) — full Sigma-based detection via Hayabusa binary
