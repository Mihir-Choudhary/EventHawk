# Sentinel — Overview

## What It Is

Sentinel is a standalone anomaly detection engine included in the `sentinel/` package. It answers a specific forensic question:

> **"Does anything in this target EVTX capture look statistically unusual compared to normal behaviour on this system?"**

Where EventHawk finds known-bad (rule matches, ATT&CK techniques, IOCs), Sentinel finds **unknown-bad** — process behaviour that deviates from established baselines even if no signature exists for it.

Sentinel is designed for advanced DFIR scenarios: detecting novel malware, living-off-the-land attacks, and attacker tradecraft that avoids known signatures.

---

## Two-Phase Architecture

Sentinel operates in two completely separate phases:

### Phase 0 — Baseline Build (offline, run once per system)

Build a statistical model of normal behaviour from a known-good EVTX corpus (e.g. 30 days of logs from a clean system).

Output: a set of baseline **artifacts** saved to disk:
- Frequency model (how often each process and command-line pattern occurs)
- Process ancestry trie (which processes spawn which children, and how deep)
- Fuse filter (probabilistic membership test for known-good process+parent+cmdline triples)
- Baseline metadata (tier boundaries, process distribution, build timestamp)

This phase runs once and its output is reused for all subsequent analyses.

### Phase 1 — Analysis (online, per investigation)

Score every process-create event in a target capture against the saved baseline:

```
For each Event 4688 or Sysmon Event 1:
  1. Normalize: cmdline → canonical form, procname → lowercase, path-stripped
  2. Score:
     a. Surprisal (command-line): how rare is this exact command for this process?
     b. Surprisal (lineage): how rare is this parent→child relationship?
     c. Trie depth: how deep is the ancestry chain vs baseline?
     d. PPID mismatch: does the reported parent PID match the actual running parent?
     e. Host drift: has this host's process distribution shifted from baseline?
  3. Composite score: weighted sum of all sub-scores
  4. Tier: 1 (normal) / 2 (review) / 3 (alert) / 4 (critical)
  5. Justification: natural-language explanation for Tier 3 and 4 events
```

---

## Tier Classification

| Tier | Score Range | Meaning | What to do |
|---|---|---|---|
| **T1** | 0 – 20 | Normal, confirmed-baseline behaviour | Ignored — suppressed from report |
| **T2** | 21 – 45 | Slightly unusual — review if investigating related activity | Summarised in aggregate |
| **T3** | 46 – 70 | Elevated — warrants direct investigation | Reviewed with full justification |
| **T4** | 71 + | **Critical** — highly anomalous, likely malicious | Prioritised finding with full context |

---

## When to Use Sentinel

| Scenario | Use Sentinel? |
|---|---|
| Novel malware with no Sigma rules | Yes ✓ |
| Living-off-the-land attacks (LOLBins) | Yes ✓ |
| Insider threat / unexpected admin activity | Yes ✓ |
| Known malware with existing Sigma rules | EventHawk + Hayabusa is faster |
| Log review for compliance (no threat) | EventHawk profiles is simpler |
| You have no baseline corpus | No — build baseline first |

---

## Sentinel vs EventHawk

| Capability | EventHawk | Sentinel |
|---|---|---|
| Known-bad detection (signatures/rules) | ✓ | Optional (Sigma pre-tagging) |
| Unknown-bad detection (anomaly scoring) | ✗ | ✓ |
| Requires baseline | No | Yes |
| Works on any event type | Yes | Process-create events (4688 / Sysmon 1) |
| GUI | Full GUI | Sentinel sub-tabs |
| CLI | Full CLI | `python -m sentinel.cli` |

The two tools are **complementary**. A typical workflow:
1. Run EventHawk with Hayabusa to catch known threats.
2. Run Sentinel to catch unknown anomalies missed by signatures.

---

## Limitations

- Sentinel only scores **process-create events** (Event 4688 for Security log, Event 1 for Sysmon). Other event types are parsed for lineage tracking but not scored.
- A meaningful baseline requires **at least 2 weeks** of clean-system logs covering all normal working hours. A thin baseline produces high false-positive rates.
- Sentinel cannot detect anomalies if the baseline was built from an already-compromised system.
- Scoring is statistical, not deterministic. A Tier 4 is a strong signal, not a confirmed compromise.
- The fuse filter has a ~0.4% false-positive rate — a known-good process can occasionally score above T1.

---

## Related Docs

- [Sentinel — Building a Baseline](16-sentinel-baseline.md)
- [Sentinel — Running Analysis](17-sentinel-analysis.md)
- [Sentinel — Sigma Rules](18-sentinel-sigma.md)
- [Sentinel CLI Reference](17-sentinel-analysis.md#cli-reference)
