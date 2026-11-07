# Building a Sentinel baseline

Choose representative process telemetry whose provenance you understand. A numerically stable baseline is not automatically clean: repetitive malicious activity can also be stable. EventHawk does not enforce a universal number of collection days or minimum event count as a guarantee of reliability.

## GUI and CLI

In **Tools > Baseline Analysis (Sentinel) > Baseline Setup**, select an input folder and output folder, optionally a Sigma folder, then **Build Baseline**. **Load Existing...** loads an existing artifact directory.

From the repository root:

```powershell
py -3.12 -m sentinel.cli build --help
py -3.12 -m sentinel.cli build --evtx .\baseline-logs --output .\baseline-artifacts
```

The input must be a directory. Discovery looks for relevant process-creation telemetry; an arbitrary `.evtx` file with unrelated events is insufficient. The builder hashes inputs and records metadata. Scoring models are built from process-creation records, not all loaded event IDs.

## Stability

The stability calculation measures normalized command-template repetition among process-creation events. Below **0.3** the build aborts; below **0.6** the validator warns. Stability is a suitability diagnostic, not an assessment that the source machine was uncompromised. Review warnings before using the model.

## Artifacts

| File | Role |
|---|---|
| baseline_meta.json | Baseline metadata, calibrated boundaries and input hashes |
| freq_model.pkl | Frequency model |
| ancestry_trie.pkl | Ancestry model |
| fuse_filter.pkl | Probabilistic matching store |
| artifact_checksums.json | Pickle-file HMAC information |
| baseline.db | Normalized event store used by offline forensic reporting |

Treat these as a directory of related artifacts, not interchangeable single model files. They can contain sensitive normalized telemetry. Use trusted artifacts: pickle loading is not a safe interchange format for an untrusted sender.

Without **SENTINEL_ARTIFACT_KEY**, the HMAC key is derived from the resolved artifact directory path. That is useful for accidental-corruption detection, not adversarial forgery protection. Moving the directory can change the derived key. A valid hexadecimal environment key provides an explicit key; an invalid hex value falls back with a warning. Use the same valid key when building/loading if you configure one.

This guide does not claim compatibility across arbitrary source/Python/dependency versions or that every artifact is authenticated against a hostile author. Rebuild from trusted originals when provenance or compatibility is in doubt.

Next: [analyze targets](17-sentinel-analysis.md).
