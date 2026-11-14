# System Activity

Open **Tools > System Activity** after loading events. The tool builds a computer-by-computer power, screen and lock history from recognized records. It works in both modes. Juggernaut counts relevant records first and asks before loading more than **200,000** into memory; that threshold is not a cap.

## Timeline and Moments

**Timeline** lists Computer, Layer, Activity, Start (UTC), End (UTC), Duration, Started by, Ended by and Notes. **Moments** shows observations with details and evidence. Computer, layer checkboxes and search control visible rows. **Hide periods under 1 s** (on by default; the checkbox shows how many) keeps split-second power transitions out of the timeline; the summary totals still count every period. The summary groups totals per layer in hours and minutes (exact totals on hover); a row's colour follows the legend under the filters. Durations in the table follow the display precision (exact on hover); the strip under the table shows the selected period or moment in full: notes, evidence and exact duration.

| Layer | Recognized evidence |
|---|---|
| Power | Kernel-General startup/shutdown, supported shutdown/crash observations, Power-Troubleshooter sleep/wake, Kernel-Power sleep/hibernation and Modern Standby 506/507 |
| Screen | Kernel-Power 566 session-type observations |
| Lock | Security 4800/4801 lock/unlock and 4802/4803 screen-saver observations |

The 566 session-type interpretation (0 screen on, 1 screen off, 3 sleep) is **inferred by the implementation**, not a Microsoft-documented mapping or proof of a person's presence. Layers reflect available records only.

Missing start/end reads **Unavailable**. A period can retain a logged boundary with unavailable duration. Unexpected-shutdown reports do not prove exact crash time. Kernel-Power 107 is not an independent wake boundary.

The model detects supported clock-change and uptime inconsistencies and reports them in Notes rather than inventing duration. Conflicting periods remain visible with disagreement notes. Power-Troubleshooter takes priority over conflicting 566 sleep timing; see [sleep reconstruction](10e-downtime-in-sessions.md).

Copies collapse by content plus occurrence number within each file. Equal-looking records occurring more than once within a file remain distinct occurrences.

## Evidence pivots and export

Right-click a period for **Events around this start/end**, or a moment for **Events around this moment**, with the offered windows. The center is the displayed boundary, even when the evidence was written later; that record remains an anchor. The Around tab uses the normalized computer scope.

**Export Timeline CSV** and **Export Moments CSV** write shown rows in shown order. CSV uses [formula-safe escaping](11-exporting.md). Times are UTC at the chosen **Precision**; durations use retained fractional values. Numeric duration is a reconstruction, not a collection-completeness guarantee.
