"""Sentinel's Sigma matching: four defects from Codex's second audit (A2-02..A2-05).

A2-02 (High): old Security 4688 events have no ParentProcessName.  The parser
stored "" and the matcher read that as a proven empty parent, so
"sel and not ParentImage|contains X" tagged every such event: a fabricated
ATT&CK tag.  Expected: a field the event lacks is unknown (no tag); a field
that is present but empty is still a real empty value.

A2-03 (High): logsource ``service`` was ignored, so a Security-only rule
tagged Sysmon events.  Expected: service security -> 4688 only, sysmon ->
Sysmon 1 only, another service -> skipped and counted.

A2-04 (Medium): the fast index lower-cased a rule's text, but the
case-insensitive regex also matches some non-ASCII letters to ASCII ones
(long s ~ s, dotted capital I ~ i), so rules the full evaluation matches were
never evaluated.  Expected: tag() equals the full evaluation.

A2-05 (Medium): a rule that can never be TRUE with the fields Sentinel keeps
was reported as "applied".  Expected: skipped, with its own reason; a rule
with at least one usable branch is still applied, and only to the event types
on which it can match.

Synthetic rules and events only, with made-up strings.  Needs pySigma (as
test_sentinel_sigma_matching): skipped with a notice without it, except in CI.
"""
import dataclasses
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rule_text(n, detection, service=None, tag="attack.t1059"):
    ls = "{category: process_creation, product: windows" + (f", service: {service}" if service else "") + "}"
    return (f"title: Zz audit rule {n}\nid: 20000000-0000-4000-8000-{n:012d}\nstatus: test\n"
            f"tags: [{tag}]\nlogsource: {ls}\ndetection:\n{detection}\nlevel: medium\n")


def missing(e):
    return getattr(e, "missing", frozenset())


def without(e, *names):
    """The event with those EventData fields absent (no-op before RawEvent.missing existed)."""
    if not hasattr(e, "missing"):
        return e
    return dataclasses.replace(e, missing=frozenset(names))


def tagger(*rules):
    from sentinel.analysis.sigma_tagger import SigmaTagger
    d = Path(tempfile.mkdtemp(prefix="sigma_a2_"))
    for i, text in enumerate(rules):
        (d / f"r{i}.yml").write_text(text, encoding="utf-8")
    return SigmaTagger(d)


def main() -> int:
    from sentinel.analysis import parser as P
    from sentinel.models import RawEvent

    # Parser: which fields the event lacks (no pySigma needed).
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    old = P._from_4688(ts, "ZZHOST", 4688, {"NewProcessName": r"C:\zz\zza.exe", "NewProcessId": "0x10",
                                            "ProcessId": "0x8", "SubjectUserName": "zzuser"})
    new = P._from_4688(ts, "ZZHOST", 4688, {"NewProcessName": r"C:\zz\zza.exe", "NewProcessId": "0x10",
                                            "ProcessId": "0x8", "SubjectUserName": "zzuser",
                                            "ParentProcessName": "", "CommandLine": "zza.exe"})
    check("parser: a 4688 without ParentProcessName records it as missing",
          "ParentProcessName" in missing(old) and "CommandLine" in missing(old), str(sorted(missing(old))))
    check("parser: a present (even empty) ParentProcessName is not missing",
          "ParentProcessName" not in missing(new) and "CommandLine" not in missing(new), str(sorted(missing(new))))
    sm = P._from_sysmon1(ts, "ZZHOST", 1, {"Image": r"C:\zz\zza.exe", "CommandLine": "", "ProcessId": "5"})
    check("parser: Sysmon 1 records its absent fields",
          {"ParentImage", "Hashes", "User"} <= missing(sm) and "CommandLine" not in missing(sm), str(sorted(missing(sm))))

    try:
        import sigma  # noqa: F401
    except ImportError:
        if os.environ.get("GITHUB_ACTIONS"):
            check("pySigma is installed in CI (requirements-lock.txt)", False)
        else:
            print("  NOTE  pySigma not installed here: matching checks not run")
        n = sum(CHECKS)
        print(f"{n}/{len(CHECKS)} checks passed")
        return 0 if n == len(CHECKS) else 1

    from sentinel.analysis.sigma_tagger import event_fields

    def ev(eid, **kw):
        base = dict(timestamp=ts, host="ZZHOST", event_id=eid, process_guid="ZZGUID" if eid == 1 else "",
                    pid=100, ppid=50, parent_guid="ZZPARENT" if eid == 1 else "", process_name="zza.exe",
                    process_path=r"C:\zz\zza.exe", parent_name="zzb.exe", parent_path=r"C:\zz\zzb.exe",
                    cmdline="zza.exe zzsafe", user="zzuser", integrity_level="Medium", image_hash="")
        base.update(kw)
        return RawEvent(**base)

    # ── A2-02: a missing parent under NOT ────────────────────────────────
    t = tagger(rule_text(1, "  sel:\n    EventID: 4688\n  filter:\n    ParentImage|contains: 'zzsafe'\n"
                            "  condition: sel and not filter"))
    no_parent = dataclasses.replace(old, process_path=r"C:\zz\zza.exe")
    check("A2-02: 4688 without a parent field is not tagged by 'not ParentImage contains'",
          t.tag(no_parent) == [], str(t.tag(no_parent)))
    check("A2-02: 4688 with a recorded, non-matching parent is tagged",
          t.tag(ev(4688)) == ["T1059"], str(t.tag(ev(4688))))
    check("A2-02: 4688 with a recorded, matching parent is not tagged",
          t.tag(ev(4688, parent_path=r"C:\zzsafe\p.exe")) == [])
    t = tagger(rule_text(2, "  sel:\n    Image|endswith: '\\zza.exe'\n    ParentImage: null\n  condition: sel"))
    check("A2-02: 'ParentImage: null' does not tag an event whose parent was not recorded",
          t.tag(no_parent) == [], str(t.tag(no_parent)))
    check("A2-02: 'ParentImage: null' tags a recorded empty parent",
          t.tag(ev(1, parent_path="")) == ["T1059"])
    t = tagger(rule_text(3, "  sel:\n    Image|endswith: '\\zza.exe'\n  filter:\n    Hashes|contains: 'zzhash'\n"
                            "  condition: sel and not filter"))
    check("A2-02: Sysmon without a Hashes field is not tagged by 'not Hashes contains'",
          t.tag(without(ev(1), "Hashes")) == [])
    check("A2-02: Sysmon with a recorded empty Hashes is a real empty value (tagged)",
          t.tag(ev(1, image_hash="")) == ["T1059"])

    # ── A2-03: logsource service ────────────────────────────────────────
    sel = "  sel:\n    CommandLine|contains: 'zzsafe'\n  condition: sel"
    t = tagger(rule_text(4, sel, service="security"))
    check("A2-03: a service: security rule does not tag a Sysmon event", t.tag(ev(1)) == [], str(t.tag(ev(1))))
    check("A2-03: a service: security rule tags a matching 4688", t.tag(ev(4688)) == ["T1059"])
    t = tagger(rule_text(5, sel, service="sysmon"))
    check("A2-03: a service: sysmon rule does not tag a 4688", t.tag(ev(4688)) == [])
    check("A2-03: a service: sysmon rule tags a matching Sysmon event", t.tag(ev(1)) == ["T1059"])
    t = tagger(rule_text(6, sel))
    check("A2-03: a rule without a service tags both", t.tag(ev(1)) == ["T1059"] and t.tag(ev(4688)) == ["T1059"])
    t = tagger(rule_text(7, sel, service="zzotherservice"))
    check("A2-03: another service is skipped and counted, not applied",
          t.status["rules_applied"] == 0 and sum(t.status["skipped"].values()) == 1
          and t.tag(ev(1)) == [] and t.tag(ev(4688)) == [], t.summary())
    t = tagger(rule_text(8, "  sel:\n    EventID: 1\n  condition: sel", service="security"))
    check("A2-03: Codex's case (service security, EventID 1) tags no Sysmon event", t.tag(ev(1)) == [])

    # ── A2-04: non-ASCII rule text vs the index ─────────────────────────
    for token, value in (("zz\u017fafe", "zza.exe zzsafe"), ("zz\u0130tem", "zza.exe zzitem"),
                         ("zzsafe", "zza.exe zz\u017fafe"), ("zzsafe", "zza.exe zzsafe")):
        t = tagger(rule_text(9, f"  sel:\n    CommandLine|contains: '{token}'\n  condition: sel"))
        e = ev(1, cmdline=value)
        full = sorted({x for r in t._rules if 1 in (r[4] if len(r) > 4 else (1,)) and r[2](event_fields(e)) is True
                       for x in r[1]})
        got = t.tag(e)
        check(f"A2-04: index equals full evaluation, rule {ascii(token)} on {ascii(value)}",
              got == full and got == ["T1059"], f"tag {got}, full {full}")

    # ── A2-05: rules that can never match ───────────────────────────────
    t = tagger(rule_text(10, "  sel:\n    ZzUnknownAuditField: 'zzmarker'\n  condition: sel"))
    check("A2-05: a rule on a field Sentinel never keeps is skipped, not applied",
          t.status["rules_applied"] == 0
          and t.status["skipped"].get("cannot match: needs fields Sentinel does not keep") == 1, t.summary())
    t = tagger(rule_text(11, "  sel_a:\n    ZzUnknownAuditField: 'zzmarker'\n"
                             "  sel_b:\n    CommandLine|contains: 'zzsafe'\n  condition: 1 of sel_*"))
    check("A2-05: a rule with one usable branch is applied and matches through it",
          t.status["rules_applied"] == 1 and t.tag(ev(1)) == ["T1059"], t.summary())
    t = tagger(rule_text(12, "  sel:\n    Hashes|contains: 'zzhash'\n  condition: sel"))
    check("A2-05: a Hashes rule is applied (Sysmon has Hashes) and runs only on Sysmon",
          t.status["rules_applied"] == 1 and t.tag(ev(1, image_hash="SHA256=zzhash")) == ["T1059"]
          and len(t._rules[0]) > 4 and t._rules[0][4] == frozenset({1}), t.summary())
    t = tagger(rule_text(13, "  sel:\n    Hashes|contains: 'zzhash'\n  condition: sel", service="security"))
    check("A2-05: a Hashes rule for service security is skipped (4688 has no Hashes)",
          t.status["rules_applied"] == 0, t.summary())
    t = tagger(rule_text(14, "  sel:\n    Image|endswith: '\\zza.exe'\n  filter:\n    ZzUnknownAuditField: 'x'\n"
                             "  condition: sel and not filter"))
    check("A2-05: 'sel and not <unknown field>' can never be TRUE: skipped",
          t.status["rules_applied"] == 0, t.summary())
    t = tagger(rule_text(15, "  keywords:\n    - 'zzkeyword'\n  condition: keywords"))
    check("A2-05: a keyword rule is applied", t.status["rules_applied"] == 1, t.summary())
    check("event_fields: the field names match _FIELDS_BY_ID",
          all({k.lower() for k in event_fields(ev(i))} == __import__(
              "sentinel.analysis.sigma_tagger", fromlist=["x"])._FIELDS_BY_ID[i] for i in (1, 4688)))

    n = sum(CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
