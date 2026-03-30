"""
Semantic Normalization Layer — translates raw Windows hex codes and integers
into human-readable descriptions.

Design principles
-----------------
* Non-destructive: only ever ADDS new ``_desc`` suffix keys to event dicts.
  Raw values (e.g. ``logon_type: 3``) are never overwritten.
* O(1) lookups: mappings are loaded once into a module-level singleton and
  held in memory for the lifetime of the process.
* Fail-safe: if a code is not in the mappings the original raw value is
  returned unchanged — never raises, never drops data.
* Zero required deps: primary mappings are in mappings.json (stdlib json).
  An optional ``mappings_user.yaml`` in ~/.evtx_tool/ extends/overrides the
  defaults if PyYAML is installed; silently skipped if not.

Public API
----------
    from evtx_tool.analysis.normalizer import SemanticNormalizer
    SemanticNormalizer.get().enrich_events(events)   # mutates in-place, adds _desc keys
    SemanticNormalizer.get().enrich(ev)              # single event
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Optional PyYAML (for user override file) ──────────────────────────────────
try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

# ── event_data field name → top-level _desc key ───────────────────────────────
# Used by _render_event_detail to show "raw → description" inline.
# Keys must be lowercase (field names are .lower()-compared at lookup time).
ED_FIELD_TO_DESC: dict[str, str] = {
    # Logon / authentication
    "logontype":                 "logon_type_desc",
    "status":                    "status_code_desc",
    "substatus":                 "sub_status_desc",
    "failurereason":             "failure_reason_desc",
    "failurecode":               "kerberos_result_desc",
    "resultcode":                "kerberos_result_desc",
    "impersonationlevel":        "impersonation_desc",
    "authenticationpackagename": "auth_pkg_desc",
    "lmpackagename":             "lm_package_desc",
    # Privilege / access
    "accessmask":                "access_mask_desc",
    "desiredaccess":             "access_mask_desc",
    "privilegelist":             "privilege_list_desc",
    # Process creation
    "tokenelevationtype":        "token_elevation_desc",
    "virtualaccount":            "virtual_account_desc",
    "elevatedtoken":             "elevated_token_desc",
    # Account management
    "newuacvalue":               "new_uac_desc",
    "olduacvalue":               "old_uac_desc",
    "mandatorylabel":            "mandatory_label_desc",
    # Object access
    "objecttype":                "object_type_desc",
    # Kerberos
    "ticketencryptiontype":      "ticket_enc_desc",
    "ticketoptions":             "ticket_options_desc",
    # Service install
    "servicetype":               "service_type_desc",
    "starttype":                 "service_start_desc",
}


class SemanticNormalizer:
    """
    Singleton semantic normalizer.

    Call ``SemanticNormalizer.get()`` to obtain the shared instance.
    Call ``enrich(ev)`` or ``enrich_events(events)`` to add _desc keys.
    """

    _instance: SemanticNormalizer | None = None

    # ── Singleton access ──────────────────────────────────────────────────────

    @classmethod
    def get(cls) -> SemanticNormalizer:
        """Return the shared instance, creating it on first call."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Initialisation ────────────────────────────────────────────────────────

    def __init__(self) -> None:
        self._maps: dict[str, dict[str, str]] = {}
        self._load_bundled()
        self._load_user_override()

    def _load_bundled(self) -> None:
        """Load the mappings.json that ships with the package."""
        try:
            import importlib.resources as _pkg_res
            # Python 3.9+ path — works whether installed via pip or run from source
            ref = _pkg_res.files("evtx_tool.data").joinpath("mappings.json")
            with ref.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception:
            # Fallback: __file__-relative path
            try:
                bundle = Path(__file__).resolve().parents[1] / "data" / "mappings.json"
                with open(bundle, encoding="utf-8") as fh:
                    raw = json.load(fh)
            except Exception as exc:
                logger.warning("SemanticNormalizer: could not load mappings.json — %s", exc)
                return

        # Strip comment keys and store all category dicts with lowercase keys
        for category, table in raw.items():
            if category.startswith("_"):
                continue
            if isinstance(table, dict):
                self._maps[category] = {k.lower(): v for k, v in table.items()}

        logger.debug("SemanticNormalizer: loaded %d categories from mappings.json",
                     len(self._maps))

    def _load_user_override(self) -> None:
        """
        Optionally merge ~/.evtx_tool/mappings_user.yaml on top of the
        bundled mappings.  Silently skipped if the file doesn't exist or
        PyYAML is not installed.
        """
        if not _HAS_YAML:
            return
        user_file = Path.home() / ".evtx_tool" / "mappings_user.yaml"
        if not user_file.exists():
            return
        try:
            with open(user_file, encoding="utf-8") as fh:
                override = _yaml.safe_load(fh) or {}
            for category, table in override.items():
                if isinstance(table, dict):
                    merged = dict(self._maps.get(category, {}))
                    merged.update({k.lower(): v for k, v in table.items()})
                    self._maps[category] = merged
            logger.debug("SemanticNormalizer: merged user override from %s", user_file)
        except Exception as exc:
            logger.warning("SemanticNormalizer: could not load user override — %s", exc)

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _norm_hex(raw) -> str:
        """
        Normalise a raw hex/int value to a canonical lowercase hex string
        suitable for dictionary lookup.

        Handles all the inconsistent shapes Windows logs produce:
          3            → "0x3"     (integer logon type)
          "3"          → "0x3"     (string logon type)
          "0xC000006D" → "0xc000006d"
          "0x0C000006D"→ "0xc000006d"  (extra leading zero)
          "C000006D"   → "0xc000006d"  (no 0x prefix)
        """
        if raw is None:
            return ""
        s = str(raw).strip().lower()
        if s.startswith("0x"):
            # Strip leading zeros after 0x but keep at least one digit.
            # FINDING-23: the old form `"0x" + stripped or "0x0"` was wrong
            # because "0x" (empty stripped) is truthy, so "0x0000" → "0x", not "0x0".
            stripped = s[2:].lstrip("0")
            s = "0x" + (stripped if stripped else "0")
        elif all(c in "0123456789abcdef" for c in s) and len(s) > 3:
            # Looks like a bare hex string with no 0x prefix
            stripped = s.lstrip("0")
            s = "0x" + (stripped if stripped else "0")
        else:
            # Treat as decimal integer → convert to hex for lookup
            try:
                s = hex(int(s))
            except (ValueError, TypeError):
                pass
        return s

    def _lookup(self, category: str, raw) -> str | None:
        """
        Try two normalised forms (direct string, hex-normalised) against a
        category dict.  Returns the description string or None on miss.
        """
        table = self._maps.get(category)
        if not table:
            return None
        # Try exact string match first (e.g. "%%2307" for FailureReasons)
        key_str = str(raw).strip().lower() if raw is not None else ""
        if key_str in table:
            return table[key_str]
        # Try hex-normalised form
        key_hex = self._norm_hex(raw)
        if key_hex and key_hex in table:
            return table[key_hex]
        return None

    def _bitwise_decode(self, category: str, raw) -> str | None:
        """
        Bitwise-AND decode for flag fields (AccessMask, TicketOptions).

        Iterates through all known bit values in the category and builds a
        human-readable composite string, e.g.:
            "ReadData / ListDirectory | ReadControl | Synchronize"
        Returns None if raw is empty or no bits match.
        """
        table = self._maps.get(category)
        if not table:
            return None
        try:
            val = int(self._norm_hex(raw), 16)
        except (ValueError, TypeError):
            return None
        matched = [
            label
            for bit_str, label in table.items()
            if _safe_int_hex(bit_str) is not None
            and val & _safe_int_hex(bit_str)
        ]
        return " | ".join(matched) if matched else None

    def _translate_privilege_list(self, raw) -> str | None:
        """
        PrivilegeList is a newline-separated list of privilege names.
        Translate each one to its description and rejoin.
        """
        if not raw:
            return None
        table = self._maps.get("Privileges")
        if not table:
            return None
        privs = [p.strip() for p in str(raw).replace("\r", "\n").split("\n") if p.strip()]
        translated = []
        for p in privs:
            desc = table.get(p.lower())
            translated.append(f"{p} ({desc})" if desc else p)
        return "\n".join(translated) if translated else None

    # ── Public enrichment API ─────────────────────────────────────────────────

    def enrich(self, ev: dict) -> None:
        """
        Add semantic _desc keys to a single event dict.
        NEVER overwrites existing keys — only adds new ones.
        All desc keys are added at the top level of ev, not inside event_data.
        """
        # FINDING-2: short-circuit if already normalized — avoids 20+ dict
        # lookups per row when _render_event_detail() is called on every click.
        if ev.get("_normalized"):
            return

        ed: dict = ev.get("event_data") or {}

        # ── LogonType ─────────────────────────────────────────────────────────
        lt = ed.get("LogonType") or ed.get("logontype")
        if lt is not None:
            desc = self._lookup("LogonTypes", lt)
            if desc:
                ev["logon_type_desc"] = desc

        # ── Status / SubStatus (NTSTATUS — with Kerberos fallback) ────────────
        # 4624/4625/4776 use NTSTATUS (0xc000006d…); 4768/4769 use Kerberos
        # result codes (0x6, 0x17, 0x18…) in the same "Status" field.
        # Try NTSTATUS first; if no match, try Kerberos result codes.
        for ed_key, desc_key in (
            ("Status",    "status_code_desc"),
            ("SubStatus", "sub_status_desc"),
        ):
            raw = ed.get(ed_key)
            if raw is not None:
                desc = self._lookup("StatusCodes", raw)
                if not desc:
                    desc = self._lookup("KerberosResultCodes", raw)
                if desc:
                    ev[desc_key] = desc

        # ── FailureReason (%%NNNN codes from 4625) ────────────────────────────
        fr = ed.get("FailureReason")
        if fr:
            desc = self._lookup("FailureReasons", fr)
            if desc:
                ev["failure_reason_desc"] = desc

        # ── Kerberos FailureCode / ResultCode (4768 / 4769 / 4771) ───────────
        for ed_key in ("FailureCode", "ResultCode"):
            krc = ed.get(ed_key)
            if krc is not None:
                desc = self._lookup("KerberosResultCodes", krc)
                if desc:
                    ev["kerberos_result_desc"] = desc
                    break

        # ── AccessMask / DesiredAccess (bitwise) ──────────────────────────────
        mask = ed.get("AccessMask") or ed.get("DesiredAccess")
        if mask:
            desc = self._bitwise_decode("AccessMaskBits", mask)
            if desc:
                ev["access_mask_desc"] = desc

        # ── TicketEncryptionType ──────────────────────────────────────────────
        tenc = ed.get("TicketEncryptionType")
        if tenc is not None:
            desc = self._lookup("TicketEncTypes", tenc)
            if desc:
                ev["ticket_enc_desc"] = desc

        # ── TicketOptions (bitwise) ───────────────────────────────────────────
        topt = ed.get("TicketOptions")
        if topt:
            desc = self._bitwise_decode("TicketOptionBits", topt)
            if desc:
                ev["ticket_options_desc"] = desc

        # ── PrivilegeList ─────────────────────────────────────────────────────
        privs = ed.get("PrivilegeList")
        if privs:
            desc = self._translate_privilege_list(privs)
            if desc:
                ev["privilege_list_desc"] = desc

        # ── ImpersonationLevel ────────────────────────────────────────────────
        impl = ed.get("ImpersonationLevel")
        if impl:
            desc = self._lookup("ImpersonationLevels", impl)
            if desc:
                ev["impersonation_desc"] = desc

        # ── AuthenticationPackageName / PackageName ───────────────────────────
        apkg = ed.get("AuthenticationPackageName") or ed.get("PackageName", "")
        if apkg:
            desc = self._lookup("LogonProcessNames", str(apkg).strip().lower())
            if desc:
                ev["auth_pkg_desc"] = desc

        # ── LmPackageName (NTLM version from 4624) ────────────────────────────
        lmpkg = ed.get("LmPackageName")
        if lmpkg and str(lmpkg).strip() not in ("-", ""):
            desc = self._lookup("LmPackageNames", str(lmpkg).strip().lower())
            if desc:
                ev["lm_package_desc"] = desc

        # ── TokenElevationType (4688 process creation) ────────────────────────
        tet = ed.get("TokenElevationType")
        if tet is not None:
            desc = self._lookup("TokenElevationType", tet)
            if desc:
                ev["token_elevation_desc"] = desc

        # ── VirtualAccount / ElevatedToken (%%1842 / %%1843 in 4624 / 4688) ───
        va = ed.get("VirtualAccount")
        if va is not None:
            desc = self._lookup("YesNo", va)
            if desc:
                ev["virtual_account_desc"] = desc

        et = ed.get("ElevatedToken")
        if et is not None:
            desc = self._lookup("YesNo", et)
            if desc:
                ev["elevated_token_desc"] = desc

        # ── NewUACValue / OldUACValue (bitwise UAC flags in 4720/4738) ─────────
        for ed_key, desc_key in (
            ("NewUACValue", "new_uac_desc"),
            ("OldUACValue", "old_uac_desc"),
        ):
            uac = ed.get(ed_key)
            if uac is not None:
                desc = self._bitwise_decode("UserAccountControlBits", uac)
                if desc:
                    ev[desc_key] = desc

        # ── ObjectType (4656 / 4663 / 4670 object access) ────────────────────
        ot = ed.get("ObjectType")
        if ot:
            desc = self._lookup("ObjectTypes", str(ot).strip().lower())
            if desc:
                ev["object_type_desc"] = desc

        # ── MandatoryLabel SID (4624 / 4688) ─────────────────────────────────
        # Windows may emit "S-1-16-12288" (SID only) or
        # "S-1-16-12288\High Mandatory Level" (SID + friendly name).
        # Take only the SID portion before any backslash or space.
        ml = ed.get("MandatoryLabel")
        if ml:
            ml_sid = str(ml).split("\\")[0].split()[0].strip().lower()
            desc = self._lookup("MandatoryLabels", ml_sid)
            if desc:
                ev["mandatory_label_desc"] = desc

        # ── ServiceType / StartType (from 7045 service install) ───────────────
        stype = ed.get("ServiceType")
        if stype is not None:
            desc = self._lookup("ServiceTypes", stype)
            if desc:
                ev["service_type_desc"] = desc

        sstart = ed.get("StartType")
        if sstart is not None:
            desc = self._lookup("ServiceStartTypes", sstart)
            if desc:
                ev["service_start_desc"] = desc

        # ── Top-level Keywords field ──────────────────────────────────────────
        kw = ev.get("keywords")
        if kw is not None:
            desc = self._lookup("Keywords", kw)
            if desc:
                ev["keywords_desc"] = desc

        # FINDING-2: mark as normalized so future calls to enrich() are no-ops.
        ev["_normalized"] = True

    def enrich_events(self, events: list[dict]) -> None:
        """Enrich an entire list of events in-place.  O(n) with O(1) per event."""
        for ev in events:
            try:
                self.enrich(ev)
            except Exception as exc:
                logger.debug("SemanticNormalizer.enrich() skipped one event: %s", exc)

    # ── Introspection helpers (used by tests / debug) ─────────────────────────

    def categories(self) -> list[str]:
        """Return the list of loaded mapping category names."""
        return list(self._maps.keys())

    def lookup(self, category: str, raw) -> str | None:
        """Public single-value lookup (returns None on miss)."""
        return self._lookup(category, raw)


# ── Module-level helper ───────────────────────────────────────────────────────

def _safe_int_hex(s: str) -> int | None:
    """Parse a hex string like '0x00100000' to int. Returns None on failure."""
    try:
        return int(s, 16)
    except (ValueError, TypeError):
        return None
