# Restarts and sleep during sessions

WiFi History and Remote Assistance Sessions adjust measured durations when loaded host-power evidence places downtime inside a session. This is EventHawk's reconstruction rule, not proof that a connection resumed after wake/restart. **Notes** and CSV exports explain each adjustment.

## Evidence used

| Boundary | Inputs recognized by the implementation |
|---|---|
| Shutdown | Kernel-General 13, EventLog 6006, Kernel-Power 109, Security 1100/4609, User32 1074 |
| Startup | Kernel-General 12, Security 4608 |
| Unexpected shutdown reported at startup | EventLog 6008, Kernel-Power 41 |
| Sleep/wake | Power-Troubleshooter 1; fallback Kernel-Power 566; supported Kernel-Power 42 to doze/hibernation evidence |

Provider/channel checks accompany these IDs; an unrelated provider's same numeric ID does not establish a boundary. Kernel-General StartTime/StopTime and record-write time form a possible boundary window when they differ. A wide/overlapping window can make duration unavailable.

## One source per sleep

Power-Troubleshooter sleep/wake timestamps take priority. A Kernel-Power 566 sleep interval is used where no Power-Troubleshooter interval covers that sleep; it is not unioned indiscriminately with conflicting timestamps.

A sleep that became hibernation can add its proven earlier sleep portion. Kernel-Power 42 is closed by the matching doze-to-hibernate record first. Only with no such doze record may the fallback extend from 42 to the Power-Troubleshooter hibernation start, supported by a 566 starting near that 42 and ending at the same wake. Matching tolerances are 60 seconds at the 42 and 5 seconds at wake. An earlier doze is not extended across an intervening awake interval.

Other 566/Power-Troubleshooter disagreements use the latter and appear in Notes. Conflict evaluation is per overlapping pair, including later starts and wake differences. Kernel-Power 107 is not accepted as an independent wake time. A sleep start without a supported wake can make a spanning session's duration unavailable.

Modern Standby 506/507 is not subtracted by this downtime model. [System Activity](10f-system-activity.md) can display it separately.

## Reading Duration and Notes

- Measurable restart/sleep inside a session is removed from the connect-to-disconnect span and marked **downtime subtracted**. Notes list the parts. Post-wake/restart time is explicitly unproven if no reconnect was recorded.
- A disconnect during sleep/wake can be treated as a connection that ended by sleep at the latest; time asleep is excluded. A disconnect within the one-minute transition tolerance is treated as a transition instead.
- Missing, unexpected, ambiguous or contradictory boundaries can yield **Unavailable** with an explanation. A connect deep inside sleep is not silently accepted as a complete measured interval.
- A session without a disconnect followed by restart is not proof of a still-active connection; notes explain the shutdown bound.

Durations use retained microsecond precision; Notes label times in UTC. Duplicate-copy handling must not erase distinct identical occurrences within one original file.
