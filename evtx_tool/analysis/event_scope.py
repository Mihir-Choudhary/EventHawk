"""Is an event from the channel and provider its event ID belongs to?

An event ID means something only for its provider: 4624 is a logon only from
Security-Auditing in the Security log, Kernel-General 12 a boot only in the
System log.  Gemini audit 8-06: the session and power builders read IDs from
any channel or provider (an application writing 4624 to the Application log
opened logon sessions; a Kernel-General 12 anywhere was a boot).

A channel or provider that is recorded must match; one that is blank is not
evidence against the event, which is read (never silently drop evidence).
The pairs were checked on the corpus: every ID read here occurs in exactly
one channel.
"""
from __future__ import annotations

SECURITY_AUDITING = "microsoft-windows-security-auditing"
EVENTLOG_SECURITY = "microsoft-windows-eventlog"      # Security 1100, 1102, 1104


def _cf(v) -> str:
    return str(v or "").strip().casefold()


def channel_of(ev) -> str:
    return _cf(ev.get("channel") or ev.get("Channel"))


def provider_of(ev) -> str:
    return _cf(ev.get("provider") or ev.get("Provider"))


def in_scope(ev, channel: str, providers=()) -> bool:
    """*ev* is in *channel* and from one of *providers* (casefold names; an
    empty *providers* accepts any), a blank field counting as a match."""
    ch, pv = channel_of(ev), provider_of(ev)
    if ch and ch != channel.casefold():
        return False
    if providers and pv and pv not in providers:
        return False
    return True


def security_event(ev) -> bool:
    """A Security-log event from Windows' own auditing (or, for the log
    service's records, the Eventlog provider)."""
    return in_scope(ev, "security", (SECURITY_AUDITING, EVENTLOG_SECURITY))


def sql_scope(channel: str, providers=()) -> str:
    """The DuckDB twin of in_scope (blank or NULL fields match)."""
    parts = [f"(channel IS NULL OR channel = '' OR lower(channel) = '{channel.casefold()}')"]
    if providers:
        names = ", ".join(f"'{p}'" for p in providers)
        parts.append(f"(provider IS NULL OR provider = '' OR lower(provider) IN ({names}))")
    return " AND ".join(parts)
