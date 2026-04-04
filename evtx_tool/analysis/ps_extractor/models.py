"""
PowerShell forensic extraction — data models.

All dataclasses used across the ps_extractor pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── Fragment / Script Block ───────────────────────────────────────────────────

@dataclass
class ScriptFragment:
    """One EID 4104 record — a single fragment of a script block."""
    message_number: int        # 1-based fragment index
    message_total: int         # expected total fragment count for this ScriptBlockId
    text: str                  # fragment content (ScriptBlockText field)
    timestamp: str             # ISO-8601 UTC from System.TimeCreated
    record_id: int             # event_record_id for provenance
    level: int                 # 3=Warning (safety-net auto-logged), 5=Verbose
    pid: str
    activity_id: str           # System.Correlation.ActivityID
    channel: str = ""          # source channel — used to detect PS Core blocks


@dataclass
class ScriptBlockAccumulator:
    """Collects all fragments for one ScriptBlockId GUID."""
    script_block_id: str
    path: str                                          # file path if loaded from disk, else ""
    computer: str
    fragments: dict[int, ScriptFragment] = field(default_factory=dict)
    # key = MessageNumber (1-based)

    @property
    def expected_total(self) -> Optional[int]:
        if not self.fragments:
            return None
        # Use max across all fragments — guards against MessageTotal inconsistency
        # (rare logging bug in older PS versions where different fragments disagree)
        return max(f.message_total for f in self.fragments.values())

    @property
    def is_complete(self) -> bool:
        t = self.expected_total
        if t is None:
            return False
        return len(self.fragments) >= t and all(
            i in self.fragments for i in range(1, t + 1)
        )

    @property
    def is_single_fragment(self) -> bool:
        return self.expected_total == 1

    @property
    def first_timestamp(self) -> str:
        return min((f.timestamp for f in self.fragments.values()), default="")

    @property
    def last_timestamp(self) -> str:
        return max((f.timestamp for f in self.fragments.values()), default="")

    @property
    def was_safety_net_triggered(self) -> bool:
        return any(f.level == 3 for f in self.fragments.values())

    def assemble(self) -> str:
        """
        Concatenate fragments in MessageNumber order.
        Missing fragments produce a [MISSING FRAGMENT N of M] placeholder.
        NUL bytes are stripped (seen on some Windows Server 2019 patch levels).
        """
        total = self.expected_total or max(self.fragments.keys(), default=1)
        parts: list[str] = []
        for i in range(1, total + 1):
            if i in self.fragments:
                parts.append(self.fragments[i].text.rstrip("\x00"))
            else:
                parts.append(f"\n[MISSING FRAGMENT {i} of {total}]\n")
        return "".join(parts)

    def missing_count(self) -> int:
        t = self.expected_total or 0
        return sum(1 for i in range(1, t + 1) if i not in self.fragments)


# ── Session ───────────────────────────────────────────────────────────────────

@dataclass
class PSSession:
    """One PowerShell engine lifetime (EID 400 → EID 403)."""
    host_id: str               # HostId GUID — primary session key
    pid: str
    computer: str
    start_ts: str              # timestamp of EID 400
    stop_ts: str               # timestamp of EID 403, or "" if not found
    host_name: str             # ConsoleHost / ServerRemoteHost / etc.
    host_version: str          # PS engine version string (e.g. "5.1.19041.1")
    host_application: str      # full command line from EID 400
    encoded_command: str       # decoded -EncodedCommand value, or ""
    runspace_id: str           # RunspaceId from EID 400
    user_sid: str = ""                                          # Security.UserID from System section
    user_name: str = ""                                         # User field from EID 4103 ContextInfo
    providers: list[str] = field(default_factory=list)       # from EID 600 events
    session_events: list[dict] = field(default_factory=list) # ordered timeline events

    def duration_str(self) -> str:
        """Return HH:MM:SS duration string, or '' if stop_ts missing."""
        if not self.start_ts or not self.stop_ts:
            return ""
        try:
            from datetime import datetime

            def _parse(ts: str):
                # Strip trailing Z
                ts = ts.rstrip("Z")
                # Truncate fractional seconds to 6 digits (%f max).
                # pyevtx-rs emits 7-9 digit fractions (e.g. ".1234567890")
                # which Python's strptime rejects — truncate to 6.
                if "." in ts:
                    base, _, frac = ts.partition(".")
                    ts = f"{base}.{frac[:6]}"
                for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        return datetime.strptime(ts, fmt)
                    except ValueError:
                        continue
                return None

            t0 = _parse(self.start_ts)
            t1 = _parse(self.stop_ts)
            if t0 and t1:
                delta = t1 - t0
                total_secs = int(delta.total_seconds())
                if total_secs < 0:
                    total_secs = 0
                h, rem = divmod(total_secs, 3600)
                m, s = divmod(rem, 60)
                return f"{h}:{m:02d}:{s:02d}"
        except Exception:
            pass
        return ""


# ── Content Analysis ──────────────────────────────────────────────────────────

@dataclass
class ContentAnalysisResult:
    """Analysis results for one assembled script block."""
    has_encoded_commands: bool
    has_download_cradle: bool
    has_amsi_bypass: bool
    has_reflection: bool
    has_process_injection: bool
    has_credential_access: bool
    has_com_objects: bool
    has_wmi_abuse: bool
    has_persistence_mechanism: bool
    has_lateral_movement: bool
    has_obfuscation: bool
    has_high_entropy_strings: bool
    detected_patterns: list[str]
    att_ck_techniques: list[str]

    def indicator_flags(self) -> list[str]:
        """Return human-readable flag names for all True boolean fields."""
        mapping = [
            ("has_encoded_commands",      "ENCODED_COMMAND"),
            ("has_download_cradle",       "DOWNLOAD_CRADLE"),
            ("has_amsi_bypass",           "AMSI_BYPASS"),
            ("has_reflection",            "REFLECTION_LOAD"),
            ("has_process_injection",     "PROCESS_INJECTION"),
            ("has_credential_access",     "CREDENTIAL_ACCESS"),
            ("has_com_objects",           "COM_OBJECT"),
            ("has_wmi_abuse",             "WMI_ABUSE"),
            ("has_persistence_mechanism", "PERSISTENCE"),
            ("has_lateral_movement",      "LATERAL_MOVEMENT"),
            ("has_obfuscation",           "OBFUSCATION"),
            ("has_high_entropy_strings",  "HIGH_ENTROPY_STRING"),
        ]
        return [label for attr, label in mapping if getattr(self, attr, False)]
