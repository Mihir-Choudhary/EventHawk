# Sentinel Sigma pre-tagging

Sentinel can tag process-creation events with the ATT&CK techniques of the Sigma rules that match them. Choose a folder of Sigma rules (`.yml` / `.yaml`) in the Baseline or Analysis tab, or pass `--sigma`:

```powershell
py -3.12 -m sentinel.cli build --evtx .\baseline-logs --output .\baseline-artifacts --sigma .\sigma-rules
py -3.12 -m sentinel.cli analyze --evtx .\incident-logs --baseline .\baseline-artifacts --sigma .\sigma-rules --report .\sentinel-report.json
```

No rules are bundled: supply the rules you intend to use. pySigma (which reads the rules) is bundled in the installer and the portable ZIP. From source it is in `requirements.txt`; without it, choosing a rules folder is an error ("Sigma rules were selected but cannot be applied"), never a silent skip.

## What is matched

pySigma reads each rule and applies its value modifiers (`contains`, `startswith`, `endswith`, `all`, `windash`, `base64`, `cased`, `re`, `cidr`, `gt`/`lt`, `fieldref`, `exists`, null, keywords). Sentinel evaluates the rule's condition (`and`, `or`, `not`, `1 of`, `all of`) against the event. An event is tagged with a rule's techniques only when the condition is **true**.

- **Which rules:** Windows `process_creation` rules, applied to Sysmon event 1 and Security event 4688. Other rules are not applied and are counted.
- **Which fields:** Sentinel keeps Image, ParentImage, CommandLine, User, IntegrityLevel, Hashes, ProcessGuid, ParentProcessGuid, ProcessId, ParentProcessId (Sysmon). For 4688: Image / NewProcessName, ParentImage / ParentProcessName, CommandLine (when command-line auditing recorded one), SubjectUserName.
- **Missing fields are unknown, not empty.** A test on a field Sentinel does not keep (ParentCommandLine, OriginalFileName, CurrentDirectory, ...) is unknown, and the condition is evaluated in three-valued logic: `not <unknown>` stays unknown, so a rule's `not filter` never passes for lack of data. Such a rule may tag fewer events than the same rule in a SIEM; it never tags more.
- **Security 4688's User** is the creator's account name, not Sysmon's `DOMAIN\user`: there a User match counts, a User miss is unknown. 4688 IntegrityLevel (a SID) and Hashes are unknown.
- **Not applied, counted by reason:** rules pySigma cannot read, files that are not plain YAML (refused before pySigma reads them), rules with no `attack.t...` technique tag, and rules using something Sentinel does not evaluate (placeholders such as `%Var%` / `expand`, regular expressions Python cannot compile).

The counts are in the run log, the CLI summary and the JSON report header (`sigma`): rules applied of rules read, skipped by reason, process-creation events checked and tagged.

Pre-tags are attached to raw events. They do not exclude matched records from baseline model construction: do not treat `--sigma` as sanitising an untrusted baseline.

[Hayabusa](10-hayabusa.md) is EventHawk's separate, full Sigma engine over every event type; Sentinel's pre-tagging covers process creation only.
