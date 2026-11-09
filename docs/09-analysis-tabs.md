# Analysis tabs

The analysis area has **ATT&CK**, **IOCs**, **Chains**, and **Bookmarks** tabs. Results depend on the analysis run's inputs, rather than automatically following later grid filters. In separate view, Analysis > This File / All Files switches the ATT&CK summary and the IOC tab between the file tab's own events and the whole collection (in Normal Mode; a Juggernaut file tab shows the collection's IOCs). Per-file IOCs keep the collection's scores and threat-intel verdicts. Chains remain the correlation run's results for the whole collection.

## ATT&CK

ATT&CK Mapping is initially enabled in Normal mode. It maps supported patterns to tactics/techniques and summarizes counts. A mapping is an investigative lead, not proof of malicious execution. Juggernaut does not provide this analysis path.

## IOCs

Enable **IOC Extraction** to collect supported addresses, domains, URLs, hashes, processes, commands, paths and identities. Results include category, count/context and heuristic scores. Ordinary administrative activity can produce the same values or scores.

Use an IOC's pivot action to inspect related events. An empty category can reflect absent fields, unsupported shapes or restricted input scope; it does not establish that an artifact never existed. **Export IOCs** is separate from event export; see [exporting](11-exporting.md). Threat-intelligence lookups are a separate user action with external-service requirements.

## Chains

Enable **Correlation Engine** to group matching evidence. Rules have their own requirements and time windows; there is no universal chain window. Expand a chain and pivot to its evidence. Optional [Hayabusa](10-hayabusa.md) detections can also appear as chains. Severity is a rule result, not a confirmed incident verdict.

## Bookmarks

Bookmark an event from the detail control or row context menu. Bookmarks are dataset/UI state, not a case-note system. Do not assume that re-parsing, clearing results or closing creates a persistent case file. Export evidence before replacing the dataset.

See [Around this event](09c-around-this-event.md).
