# Hayabusa integration

Hayabusa is an optional external tool. EventHawk does not bundle its rules or install it automatically. Obtain a compatible executable and rules from the [Hayabusa project](https://github.com/Yamato-Security/hayabusa), following that version's instructions.

Enable **Hayabusa Rules** and use **Browse...** to select the executable. EventHawk considers a configured binary, PATH, then built-in candidate locations. A missing executable is not a zero-detection result.

The integration runs a separate process against EVTX input paths and converts JSONL results to detection chains. Filtering the EventHawk grid does not rewrite those files; do not assume Hayabusa analyzed only currently visible rows. Review rules/severity in **Chains** and pivot to evidence. Benign activity can match a rule.

Distinguish execution failure, cancellation or malformed output from a successful run with no matches. This guide establishes no fixed rule count, throughput, collection-size limit or compatibility with every Hayabusa release. There is no EventHawk CLI `--hayabusa` option.

See [analysis](09-analysis-tabs.md) and [performance](19-performance.md).
