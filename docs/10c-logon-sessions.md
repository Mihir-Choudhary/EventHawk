# Logon Sessions

Open **Tools > View Logon Sessions** after loading events. The browser reconstructs logons with identity, logon type, start/end information, activity and notes. **Hide service sessions (Type 5)** changes visible browser rows. **Hide system accounts** (on by default, with a count) leaves out Windows' own accounts: SYSTEM, LOCAL SERVICE, NETWORK SERVICE, the font driver (UMFD-n), the window manager (DWM-n) and the computer account (NAME$); untick it to see them. Pale red rows hold dangerous privileges, pale yellow rows have no logoff recorded; hover a logon type for what it means.

Selecting a row alone does not filter the grid. Use **Filter to Selected Session**, the corresponding row action or session activation. **Clear Session Filter** removes that restriction; other grid filters can still apply.

## Identity and boundaries

Logon IDs are scoped by computer and available boot evidence, including Security **4608** and Kernel-General **12**. A Windows session ID differs from a security logon LUID. Username alone is not a session identity.

Reconstruction uses available logon/logoff and linked-session evidence. Last activity is not automatically a logoff. Missing boundaries and conflicts must be read with the notes. A logon lifetime can include disconnected remote-session time.

Filtering finds events associated with the selected reconstructed session; it is not merely a time range or username search. Juggernaut fetches relevant full records from Parquet. A large session filter asks for confirmation above **100,000** matching events.

Missing boot/logoff records cannot rule out reboot or ID reuse. Preserve source evidence when reporting a reconstruction. For connected intervals see [remote sessions](10d-inbound-rdp.md) and [downtime](10e-downtime-in-sessions.md).
