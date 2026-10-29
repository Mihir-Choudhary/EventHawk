# Inbound RDP intervals

Open **Tools > Remote Assistance Sessions** to inspect destination-side RDP
evidence alongside the other remote-access artifacts. Inbound rows have type
**RDP Session**. `LOCAL_CONSOLE` means LSM recorded local console activity;
that row is not proof of access from another computer.

Each LSM 21 logon or 25 reconnect starts a separate row. A matching 23 logoff
or 24 disconnect ends that interval; 39/40 can also prove a disconnect. A
new start with the same SessionID always starts another row. Event 22 is a
shell notification and 41 is arbitration, so neither proves a boundary.
RemoteConnectionManager 1149 proves authentication, not a session start.
Unpaired authentication and diagnostic observations remain visible with
Unavailable duration. The number of rows is therefore not a count of distinct
remote connections.

An interval has a numeric duration only when its own start and end are logged,
the timestamps are readable and ordered, and the identifiers do not conflict.
Missing boundaries read **Unavailable**. An unpaired start has status
**Start logged (no end)**; it does not prove that
the session is still active. Loaded Security 4608 and
Kernel-General 12 system-start events prevent pairing across a reboot. Missing
telemetry cannot establish that a reboot or reuse did not occur.

The **Row** column is a stable reference assigned when the browser opens.
When a disconnect is followed by a reconnect with the same computer,
SessionID and full user identity, with no intervening logon, logoff or loaded
reboot, the new row says **continues the session in row N (reconnect)** in
**Continuity**. Both rows remain separate, with their own evidence and durations;
the disconnected gap is not counted as connected time. This correlation uses
the loaded evidence and cannot rule out unlogged ID reuse.

Sorting and filtering do not renumber Row. A referenced row may be hidden by
the browser's filters; clear those filters to find it. CSV export preserves Row
and Continuity in the current sort order, including when only part of a chain
is exported. **Filter to Session** includes that row's records, not the records
of its referenced predecessor. Copies of the same record do not create extra
intervals; all their source keys remain available to the filter.

Security logon LUIDs and LSM SessionIDs are separate namespaces and are never
merged by username, peer address or time proximity. Security 4624 type 10 to
4634 measures a **logon lifetime**, which may include disconnected time.
4778/4779 use their documented `LogonID` field for separate connection
intervals. The Evidence column identifies the namespace and boundary events.

These rules concern inbound reconstruction. The other remote-access types have
different telemetry and do not establish inbound RDP connection durations.
