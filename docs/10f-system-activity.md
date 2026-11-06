# System Activity

**Tools > System Activity** shows, for each computer, when it was on, when its
screen was on or off, when it was asleep or hibernating, when it was shut down or
off after a crash, and when it was locked. Every period shows the event that
proves its start and the event that proves its end. A time the events do not
prove reads **Unavailable**; EventHawk never fills one in.

It works in Normal and Juggernaut mode. In Juggernaut mode it loads only the
events it reads, and asks first when they are many (as WiFi History does).

## The two tabs

**Timeline** lists periods: Computer, Layer, Activity, Start, End, Duration,
Started by, Ended by and Notes. Times are UTC at the precision chosen under
**Precision**; durations are exact to the microsecond.

| Layer | Activity | Proven by |
|---|---|---|
| Power | On | from a start (Kernel-General 12 `StartTime`) or a wake, to a shutdown or a sleep |
| Power | Sleep, Hibernate | Power-Troubleshooter 1: exact `SleepTime` and `WakeTime`; the target state tells sleep (S1 to S3) from hibernation (S4). A sleep that turns into hibernation shows as a Sleep followed by a Hibernate |
| Power | Modern Standby | Kernel-Power 506 (entering) to 507 (exiting) |
| Power | Shut down | from the shutdown (Kernel-General 13 `StopTime`, EventLog 6006, Kernel-Power 109, Security 1100/4609, User32 1074) to the next start |
| Power | Off (unexpected shutdown) | Windows reports the crash at the next start (Kernel-Power 41, EventLog 6008). The moment it stopped is not logged: the start reads Unavailable and the notes quote the time Windows gives in 6008 (that machine's local time) |
| Screen | Screen on, Screen off | Kernel-Power 566 (Windows 10 version 2004 and later, Windows 11) |
| Lock | Locked, Screen saver | Security 4800 to 4801, 4802 to 4803 |

**Moments** lists single events: Windows started or shut down, boot type
(Kernel-Boot 27: cold boot, fast startup or resume from hibernation), who or what
asked for a shutdown or restart (User32 1074: process, user, type, reason), the
shutdown action (Kernel-Power 109), going to sleep with its reason (Kernel-Power
42: Button or Lid, System Idle, Battery...), waking with its wake source
(Power-Troubleshooter 1), screen changes with their reason (Kernel-Power 566:
keyboard or mouse, movement, unlock, sleep...), lock and unlock (including unlock
logons, 4624 type 7), console logon and logoff (Winlogon 7001/7002), clock
changes (Kernel-General 1, Security 4616), AC or battery (Kernel-Power 105),
Windows' uptime counter (EventLog 6013), and boot and shutdown durations
(Diagnostics-Performance 100/200).

The summary line adds up each activity for the chosen computer. Periods with an
unknown start or end are not in the totals; the line says how many.

## What to know

- **Screen on / off.** Kernel-Power 566 records a "session" change with the
  length of the session that ended. Windows does not name the session types. In
  the test logs type 0 behaves as screen on, 1 as screen off and 3 as sleep:
  every change into 3 coincides with a sleep, every change out of it with a
  Power-Troubleshooter wake, the first session after a start is type 0 and lasts
  from the start, and changes from 1 to 0 are caused by keyboard, mouse,
  movement or power events. The tool shows the type number next to the label.
  Consecutive 566 records are the boundaries; where Windows' session length
  differs from the time between them by more than 5 seconds, the notes say so.
- **Kernel-Power 107 ("resumed") is not used as a wake time.** It is written
  with the clock from before the sleep: in the test logs a sleep from 14:03 to
  14:18 has its 107 at 14:03:09. A sleep without a Power-Troubleshooter 1 or a
  Kernel-Power 566 ends Unavailable, and the notes give the 107 time with this
  warning.
- **Clock changes.** If the system clock was changed by a minute or more inside
  a period (other than the correction Windows makes just after a wake), or
  Windows' uptime counter disagrees with the clock by more than 10 minutes, that
  period's duration is Unavailable and the notes give the change. Start and end
  are still shown as logged.
- **Conflicting events.** When the events place two periods on top of each
  other, or a start inside a sleep, both stay and both notes say "the logged
  events disagree".
- **Lock events** need the Security policy *Audit Other Logon/Logoff Events*,
  which is off by default. Without it there is no Lock layer.
- **Copies of the same log** count once.

## Jumping to the evidence

Right-click a period for **Events around this start** or **Events around this
end** (±5 or ±30 minutes), or a moment for **Events around this moment**. This
opens an [Around This Event](09c-around-this-event.md) tab on that machine.

## Export

**Export Timeline CSV** and **Export Moments CSV** write the rows shown, in the
order shown. Cells are formula-safe (see [Exporting](11-exporting.md)).
