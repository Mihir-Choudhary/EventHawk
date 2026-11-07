# Sentinel Sigma pre-tagging

Sigma integration is optional. Sentinel's additional requirements file lists pySigma; the main application's requirements do not install it. Missing pySigma disables pre-tagging with a warning. It does not prevent Sentinel's non-Sigma analysis.

To prepare a separate source environment for this optional feature, install its requirements there:

```powershell
py -3.12 -m pip install -r sentinel/requirements.txt
```

No rule collection is bundled by this step. Supply a directory of rules you intend to use. CLI forms are:

```powershell
py -3.12 -m sentinel.cli build --evtx .\baseline-logs --output .\baseline-artifacts --sigma .\sigma-rules
py -3.12 -m sentinel.cli analyze --evtx .\incident-logs --baseline .\baseline-artifacts --sigma .\sigma-rules --report .\sentinel-report.json
```

## Actual matching behavior

The loader scans `.yml` files and uses pySigma to load rule metadata. The current tagger builds **heuristic predicates from rule-title keywords**, retaining ATT&CK technique tags. It does not evaluate complete Sigma selections, conditions, modifiers, correlations or a backend query. This distinction applies even if the rules load successfully.

A tag therefore means this heuristic matched; it is not a validated Sigma-rule detection. The GUI/logging identifies keyword mode. Empty/invalid rule inputs or missing dependencies require checking warnings, not treating zero tags as proof of no suspicious activity.

Pre-tags are attached to available raw events. They do not automatically exclude matched records from baseline model construction. Do not claim that --sigma sanitizes an otherwise untrusted baseline.

Use [Hayabusa](10-hayabusa.md) for the separate external integration; it is not the same engine as this heuristic pre-tagger.
