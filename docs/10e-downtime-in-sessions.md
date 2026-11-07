# Restarts and sleep during a session

A Wi-Fi connection or a remote session cannot continue while its computer is
switched off or asleep. When the logs show that the computer was down or asleep
during a session, **Tools > WiFi History** and **Tools > Remote Assistance
Sessions** take that time out of the session's duration and explain it in the
**Notes** column (also in their CSV exports).

## What EventHawk reads

| Kind | Events |
|---|---|
| Shutdown | Kernel-General 13 (with the exact stop time), EventLog 6006, Kernel-Power 109, Security 1100 / 4609, User32 1074 (shutdown started) |
| Startup | Kernel-General 12 (with the exact start time), Security 4608 |
| Unexpected shutdown | EventLog 6008, Kernel-Power 41 (written at the next startup; the moment of the crash is not logged) |
| Sleep | One source per sleep. Power-Troubleshooter 1 (exact sleep and wake times) first; Kernel-Power 566 (a sleep session with its exact length, Windows 10 2004 and later) only where no Power-Troubleshooter 1 covers that sleep. A sleep that turned into hibernation adds its sleep part: from Kernel-Power 42 (going to sleep) to the "doze to hibernate" record, or, with no doze record, to the hibernation's start when a Kernel-Power 566 for the same sleep starts at that 42 and ends at the same wake. When a 566 disagrees with Power-Troubleshooter 1 otherwise, the Power-Troubleshooter times are used and the Notes say so. Kernel-Power 107 (resumed) is not used: it is written with the clock from before the sleep. A sleep whose wake time is not known leaves a session across it with no duration, and the Notes say why |

Modern Standby (Kernel-Power 506/507) is not counted: the network can stay
connected in it. Copies of the same log count each event once.

## What the Duration shows

- **A clean restart or a sleep inside the session:** the duration is the
  connect-to-disconnect span minus the time the computer was down or asleep,
  marked **(downtime subtracted)**. Notes give every part: the time before the
  shutdown or sleep (the connection lasted until then at the latest), each period
  down or asleep with its times and the events that prove them, and the time
  after the restart or wake. That last part is **not proven**: no new connection
  was logged after the computer came back, so EventHawk cannot show that the same
  connection resumed. Every duration here is exact to the microsecond the log
  records (a fraction shows only when there is one), so the parts in Notes add
  up exactly to the span and to the duration shown; nothing is rounded.
- **A disconnect logged while the computer was asleep or waking** (Windows often
  logs the lost connection when it wakes): the connection ended by the sleep at
  the latest, so the time asleep is not counted, and Notes say so.
- **A disconnect logged as the computer goes to sleep** (within a minute of the
  sleep starting): nothing changes.
- **Unavailable**, with the reason in Notes, when a restart lies inside the
  session but its downtime cannot be measured: the shutdown was unexpected or not
  logged, or the startup or shutdown time is uncertain (a recorded start or stop
  time more than a minute away from the record's own time), or a startup or a
  sleep reaches across the session's start or end.
- **A session with no disconnect logged** that is followed by a restart is never
  shown as Active; Notes give the shutdown it ended by at the latest.

The flags column marks these rows: `downtime_subtracted`, `reboot_between`,
`reboot_uncertain`, `sleep_uncertain` (Remote Assistance: `DOWNTIME_SUBTRACTED`,
`REBOOT_BETWEEN`, `REBOOT_UNCERTAIN`, `SLEEP_UNCERTAIN`, `REBOOT_AFTER_START`).
All times in Notes are UTC.
