"""Sentinel tags events by what Sigma rules detect, not by words of their titles.

Sentinel's Sigma pre-tagging used pySigma only to read the rules, then tagged
an event with a rule's ATT&CK techniques when two words of the rule's TITLE
appeared in its command line.  Four synthetic lines, two rules: the two lines
the rules detect got no tag, and a harmless line naming the title's words got
a false technique.  Without pySigma (the packaged app) a selected rules folder
was skipped with only a log line.

Expected:
  - an event is tagged when the rule's detection matches it, and only then
    (contains / endswith / all / re / cased / windash / null / keywords /
    "1 of" / not);
  - a test on a field Sentinel does not keep is unknown: "not <that>" never
    tags an event (Security 4688's User is the creator's name: a miss there
    is unknown too);
  - only Windows process_creation rules are applied, only to Sysmon 1 and
    Security 4688; skipped rules are counted by reason;
  - tags in any letter case, *.yaml files, every YAML document;
  - pySigma missing -> SigmaUnavailable, never a silent skip.

Synthetic rules and events only, with made-up strings.  Needs pySigma: it
is in requirements-lock.txt (the release build and CI); elsewhere the
matching checks are skipped with a notice, except in CI where that fails.
"""
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rule(rid, title, tags, detection, category="process_creation", product="windows"):
    tag_txt = ", ".join(tags)
    return (f"title: {title}\nid: {rid}\nstatus: test\ntags: [{tag_txt}]\n"
            f"logsource: {{category: {category}, product: {product}}}\n"
            f"detection:\n{detection}\nlevel: medium\n")


RULES = {
    # 1: bare zzdemo.exe, no arguments.
    "r01.yml": rule("00000000-0000-4000-8000-000000000001", "Zzdemo Execution Without Arguments",
                    ["attack.defense-evasion", "attack.t1218.011"],
                    "  sel:\n    Image|endswith: '\\zzdemo.exe'\n    CommandLine|endswith: 'zzdemo.exe'\n"
                    "  condition: sel"),
    # 2: a marker string anywhere in the command line.  Title words differ.
    "r02.yml": rule("00000000-0000-4000-8000-000000000002", "Credential Dumping Tool Usage",
                    ["attack.credential-access", "ATTACK.T1003.001"],
                    "  sel:\n    CommandLine|contains: 'zzmarker::alpha'\n  condition: sel"),
    # 3: "not filter" on a field Sentinel lacks (ParentCommandLine).
    "r03.yml": rule("00000000-0000-4000-8000-000000000003", "Yydemo Spawn",
                    ["attack.t1059"],
                    "  sel:\n    Image|endswith: '\\yydemo.exe'\n"
                    "  filter:\n    ParentCommandLine|contains: 'zzsafe'\n"
                    "  condition: sel and not filter"),
    # 4: "not filter" on a field Sentinel has (ParentImage).
    "r04.yml": rule("00000000-0000-4000-8000-000000000004", "Xxdemo Spawn",
                    ["attack.t1106"],
                    "  sel:\n    Image|endswith: '\\xxdemo.exe'\n"
                    "  filter:\n    ParentImage|endswith: '\\zzparent.exe'\n"
                    "  condition: sel and not filter"),
    # 5: contains|all + windash + regex + cased, 1 of sel*.
    "r05.yaml": rule("00000000-0000-4000-8000-000000000005", "Wwdemo Flags",
                     ["attack.t1027"],
                     "  sel_all:\n    CommandLine|contains|all: ['-aa1', '-bb2']\n"
                     "  sel_dash:\n    CommandLine|windash|contains: '-qq9'\n"
                     "  sel_re:\n    CommandLine|re: 'zzre[0-9]{3}x'\n"
                     "  sel_cased:\n    CommandLine|cased|contains: 'ZzCaSe'\n"
                     "  condition: 1 of sel_*"),
    # 6: User filter: Sysmon exact, Security 4688 only partial.
    "r06.yml": rule("00000000-0000-4000-8000-000000000006", "Vvdemo Not System",
                    ["attack.t1569"],
                    "  sel:\n    Image|endswith: '\\vvdemo.exe'\n"
                    "  filter:\n    User|contains: 'ZZ AUTHORITY'\n"
                    "  condition: sel and not filter"),
    # 7: keyword.
    "r07.yml": rule("00000000-0000-4000-8000-000000000007", "Keyword Demo",
                    ["attack.t1105"],
                    "  keywords:\n    - 'zzkeyword77'\n  condition: keywords"),
    # 8: null: ParentImage empty.
    "r08.yml": rule("00000000-0000-4000-8000-000000000008", "Orphan Demo",
                    ["attack.t1036"],
                    "  sel:\n    Image|endswith: '\\uudemo.exe'\n    ParentImage: null\n  condition: sel"),
    # 12: plain contains, for the look-alike-letter case.
    "r12.yml": rule("00000000-0000-4000-8000-000000000012", "Long S Demo",
                    ["attack.t1140"],
                    "  sel:\n    CommandLine|contains: 'zzlongs'\n  condition: sel"),
    # 13: startswith + base64offset + wide (UTF-16) base64, 1 of them.
    "r13.yml": rule("00000000-0000-4000-8000-000000000013", "Encoded Demo",
                    ["attack.t1132"],
                    "  s_start:\n    CommandLine|startswith: 'zzstart'\n"
                    "  s_b64:\n    CommandLine|base64offset|contains: 'zzb64marker'\n"
                    "  s_wide:\n    CommandLine|wide|base64offset|contains: 'zzwidemark'\n"
                    "  condition: 1 of them"),
    # 14: number comparison, field reference, exists, all of them.
    "r14.yml": rule("00000000-0000-4000-8000-000000000014", "Compare Demo",
                    ["attack.t1057"],
                    "  sel_img:\n    Image|endswith: '\\ttdemo.exe'\n"
                    "  sel_pid:\n    ProcessId|gt: 500\n"
                    "  sel_ref:\n    Image|fieldref: ParentImage\n"
                    "  sel_cmd:\n    CommandLine|exists: true\n"
                    "  condition: all of them"),
    # 15: exists:false on a field Sentinel does not keep -> unknown.
    "r15.yml": rule("00000000-0000-4000-8000-000000000015", "Exists Demo",
                    ["attack.t1027.005"],
                    "  sel:\n    Image|endswith: '\\ssdemo.exe'\n    OriginalFileName|exists: false\n"
                    "  condition: sel"),
    # 16: not 1 of filter_*, and "not ParentImage: null".
    "r16.yml": rule("00000000-0000-4000-8000-000000000016", "Filters Demo",
                    ["attack.t1204"],
                    "  sel:\n    Image|endswith: '\\rrdemo.exe'\n"
                    "  filter_a:\n    CommandLine|contains: 'zzskipa'\n"
                    "  filter_b:\n    ParentImage|endswith: '\\zzskipb.exe'\n"
                    "  filter_null:\n    ParentImage: null\n"
                    "  condition: sel and not 1 of filter_*"),
    # 17: Security 4688 without a recorded command line, under a not-filter.
    "r17.yml": rule("00000000-0000-4000-8000-000000000017", "No Cmdline Demo",
                    ["attack.t1033"],
                    "  sel:\n    Image|endswith: '\\qqdemo.exe'\n"
                    "  filter:\n    CommandLine|contains: 'zzharmless'\n"
                    "  condition: sel and not filter"),
    # Not applied: another category, no technique, a broken rule.
    "r09.yml": rule("00000000-0000-4000-8000-000000000009", "Network Demo", ["attack.t1071"],
                    "  sel:\n    DestinationPort: 4444\n  condition: sel", category="network_connection"),
    "r10.yml": rule("00000000-0000-4000-8000-000000000010", "Untagged Demo", ["attack.execution"],
                    "  sel:\n    Image|endswith: '\\zzdemo.exe'\n  condition: sel"),
    "r11.yml": rule("00000000-0000-4000-8000-000000000011", "Broken Demo", ["attack.t1000"],
                    "  sel:\n    Image|nosuchmodifier: 'x'\n  condition: sel"),
}


def ev(eid, cmd, img, parent=r"C:\Windows\explorer.exe", user=r"ZZHOST\zzuser", pid=100):
    from sentinel.models import RawEvent
    return RawEvent(timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc), host="ZZHOST", event_id=eid,
                    process_guid="", pid=pid, ppid=50, parent_guid="",
                    process_name=img.rsplit("\\", 1)[-1], process_path=img,
                    parent_name=parent.rsplit("\\", 1)[-1] if parent else "", parent_path=parent,
                    cmdline=cmd, user=user, integrity_level="Medium", image_hash="")


def b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


def main() -> int:
    import builtins
    from sentinel.analysis import sigma_tagger as ST

    d = Path(tempfile.mkdtemp(prefix="sigmatch_"))
    for name, text in RULES.items():
        (d / name).write_text(text, encoding="utf-8")

    # pySigma missing: an error, never a silent skip.
    real_import = builtins.__import__

    def no_sigma(name, *a, **k):
        if name == "sigma" or name.startswith("sigma."):
            raise ImportError("No module named 'sigma'")
        return real_import(name, *a, **k)
    builtins.__import__ = no_sigma
    try:
        try:
            ST.SigmaTagger(d)
            raised = None
        except ST.SigmaUnavailable as exc:
            raised = str(exc)
    finally:
        builtins.__import__ = real_import
    check("pySigma missing: SigmaUnavailable, not a silent skip", raised and "pySigma" in raised, str(raised))

    try:
        import sigma.collection  # noqa: F401
    except ImportError:
        if os.environ.get("GITHUB_ACTIONS"):
            check("pySigma is installed in CI (requirements-lock.txt)", False)
        else:
            print("  NOTE  pySigma not installed here: matching checks not run")
        n = sum(ok for _, ok in CHECKS)
        print(f"{n}/{len(CHECKS)} checks passed")
        return 0 if n == len(CHECKS) else 1

    t = ST.SigmaTagger(d)
    st = t.status
    # r03 and r15 can never be TRUE (every path needs ParentCommandLine or
    # OriginalFileName, which Sentinel does not keep): skipped and counted,
    # not "applied" (Codex audit A2-05).  They still tag nothing below.
    check("12 rules applied", st["rules_applied"] == 12, t.summary())
    check("r03 and r15 skipped: cannot match with Sentinel's fields",
          st["skipped"].get("cannot match: needs fields Sentinel does not keep") == 2, str(st["skipped"]))
    check("skipped by reason: other category 1, no technique 1, unreadable 1",
          st["skipped"].get("not a Windows process_creation rule") == 1
          and st["skipped"].get("no ATT&CK technique tag") == 1
          and st["skipped"].get("rule pySigma cannot read") == 1, str(st["skipped"]))

    W = r"C:\Windows\System32"
    cases = [
        # (name, event, expected tags)
        ("zzdemo with arguments: no tag", ev(1, W + r"\zzdemo.exe one,two", W + r"\zzdemo.exe"), []),
        ("bare zzdemo: rule 1", ev(1, W + r"\zzdemo.exe", W + r"\zzdemo.exe"), ["T1218.011"]),
        ("marker in command line: rule 2 (tag read in upper case)",
         ev(1, r"zz.exe x zzmarker::alpha y", r"C:\t\zz.exe"), ["T1003.001"]),
        ("the title's words only: no tag (the old false tag)",
         ev(1, r"notepad.exe C:\notes\credential dumping tool usage.txt", W + r"\notepad.exe"), []),
        ("not-filter on a field Sentinel lacks: unknown, no tag",
         ev(1, "yydemo.exe", r"C:\t\yydemo.exe"), []),
        ("not-filter on ParentImage, filter false: rule 4",
         ev(1, "xxdemo.exe", r"C:\t\xxdemo.exe"), ["T1106"]),
        ("not-filter on ParentImage, filter true: no tag",
         ev(1, "xxdemo.exe", r"C:\t\xxdemo.exe", parent=r"C:\t\zzparent.exe"), []),
        ("contains|all, both present: rule 5", ev(1, "w.exe -aa1 -bb2", r"C:\t\w.exe"), ["T1027"]),
        ("contains|all, one present: no tag", ev(1, "w.exe -aa1", r"C:\t\w.exe"), []),
        ("windash: slash form matches", ev(1, "w.exe /qq9", r"C:\t\w.exe"), ["T1027"]),
        ("regex matches", ev(1, "w.exe zzre123x", r"C:\t\w.exe"), ["T1027"]),
        ("cased: other case does not match", ev(1, "w.exe zzcase", r"C:\t\w.exe"), []),
        ("cased: same case matches", ev(1, "w.exe ZzCaSe", r"C:\t\w.exe"), ["T1027"]),
        ("Sysmon User not the filtered one: rule 6", ev(1, "vvdemo.exe", r"C:\t\vvdemo.exe"), ["T1569"]),
        ("Sysmon User the filtered one: no tag",
         ev(1, "vvdemo.exe", r"C:\t\vvdemo.exe", user=r"ZZ AUTHORITY\SYSTEM"), []),
        ("Security 4688 User is only the account name: unknown, no tag",
         ev(4688, "vvdemo.exe", r"C:\t\vvdemo.exe", user="zzuser"), []),
        ("Security 4688 Image test works", ev(4688, W + r"\zzdemo.exe", W + r"\zzdemo.exe"), ["T1218.011"]),
        ("keyword anywhere in the command line: rule 7",
         ev(1, "k.exe --x=zzkeyword77--", r"C:\t\k.exe"), ["T1105"]),
        ("null: empty ParentImage matches", ev(1, "uudemo.exe", r"C:\t\uudemo.exe", parent=""), ["T1036"]),
        ("null: a ParentImage present does not", ev(1, "uudemo.exe", r"C:\t\uudemo.exe"), []),
        ("not a process-creation event (Sysmon 5): no tag",
         ev(5, W + r"\zzdemo.exe", W + r"\zzdemo.exe"), []),
        ("plain contains: rule 12", ev(1, "q.exe zzlongs", r"C:\t\q.exe"), ["T1140"]),
        # The regex matcher treats U+017F (long s) as "s" without case; the
        # quick text check must not skip the rule for it.
        ("look-alike letter (long s): matched as the evaluator does",
         ev(1, "q.exe zzlong\u017f", r"C:\t\q.exe"), ["T1140"]),
        ("startswith: matches at the start", ev(1, "zzstart.exe /x", r"C:\t\e.exe"), ["T1132"]),
        ("startswith: not in the middle", ev(1, "e.exe zzstart", r"C:\t\e.exe"), []),
        ("base64offset: the encoded marker matches",
         ev(1, "e.exe -enc " + b64(b"zzb64marker tail"), r"C:\t\e.exe"), ["T1132"]),
        ("base64offset: the marker at offset 1 matches",
         ev(1, "e.exe -enc " + b64(b"x" + b"zzb64marker tail"), r"C:\t\e.exe"), ["T1132"]),
        ("wide base64: UTF-16 encoded marker matches",
         ev(1, "e.exe -enc " + b64("zzwidemark!".encode("utf-16-le")), r"C:\t\e.exe"), ["T1132"]),
        ("encoded text not containing the marker: no tag",
         ev(1, "e.exe -enc " + b64(b"something else entirely"), r"C:\t\e.exe"), []),
        ("all of them: pid > 500, Image = ParentImage, CommandLine exists",
         ev(1, "ttdemo.exe", r"C:\t\ttdemo.exe", parent=r"C:\t\ttdemo.exe", pid=900), ["T1057"]),
        ("all of them: pid 100 is not > 500",
         ev(1, "ttdemo.exe", r"C:\t\ttdemo.exe", parent=r"C:\t\ttdemo.exe", pid=100), []),
        ("all of them: fieldref differs", ev(1, "ttdemo.exe", r"C:\t\ttdemo.exe", pid=900), []),
        ("all of them on 4688: ProcessId not kept -> unknown, no tag",
         ev(4688, "ttdemo.exe", r"C:\t\ttdemo.exe", parent=r"C:\t\ttdemo.exe", pid=900), []),
        ("exists:false on a field Sentinel lacks: unknown, no tag",
         ev(1, "ssdemo.exe", r"C:\t\ssdemo.exe"), []),
        ("not 1 of filter_*: no filter true -> rule 16", ev(1, "rrdemo.exe", r"C:\t\rrdemo.exe"), ["T1204"]),
        ("not 1 of filter_*: filter_a true -> no tag", ev(1, "rrdemo.exe zzskipa", r"C:\t\rrdemo.exe"), []),
        ("not 1 of filter_*: filter_b true -> no tag",
         ev(1, "rrdemo.exe", r"C:\t\rrdemo.exe", parent=r"C:\x\zzskipb.exe"), []),
        ("not 1 of filter_*: empty ParentImage (filter_null) -> no tag",
         ev(1, "rrdemo.exe", r"C:\t\rrdemo.exe", parent=""), []),
        ("4688 with no command line recorded, not-filter on it: unknown, no tag",
         ev(4688, "", r"C:\t\qqdemo.exe"), []),
        ("4688 with a command line, filter false: rule 17", ev(4688, "qqdemo.exe /a", r"C:\t\qqdemo.exe"),
         ["T1033"]),
        ("Sysmon with an empty command line is a real empty value: rule 17",
         ev(1, "", r"C:\t\qqdemo.exe"), ["T1033"]),
    ]
    for name, e, want in cases:
        got = t.tag(e)
        check(name, got == want, f"got {got}, want {want}")
    # The quick text index changes no result: every rule evaluated -> same tags.
    fast = [t.tag(e) for _, e, _ in cases]
    index, always = t._index, t._always
    t._index, t._always = {}, list(range(len(t._rules)))
    full = [t.tag(e) for _, e, _ in cases]
    t._index, t._always = index, always
    for _ in range(2):          # undo the extra counting of the two passes
        st["events_checked"] -= sum(1 for _, e, _ in cases if e.event_id in (1, 4688))
        st["events_tagged"] -= sum(1 for _, _, w in cases if w)
    check("the quick text index gives the same tags as evaluating every rule", fast == full,
          f"{fast} vs {full}")
    check("events counted: process-creation events checked and tagged",
          st["events_checked"] == sum(1 for _, e, _ in cases if e.event_id in (1, 4688))
          and st["events_tagged"] == sum(1 for _, _, w in cases if w), t.summary())

    # Every YAML document of a file is checked before pySigma reads it.
    d2 = Path(tempfile.mkdtemp(prefix="sigmatch2_"))
    (d2 / "two.yml").write_text(RULES["r01.yml"] + "---\n!!python/name:builtins.len\n",
                                encoding="utf-8")
    t2 = ST.SigmaTagger(d2)
    check("a file with a non-data YAML document is refused whole",
          t2.status["rules_applied"] == 0
          and t2.status["skipped"].get("file not readable as plain YAML") == 1, t2.summary())

    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
