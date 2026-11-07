"""STIX / MISP / YARA exports follow their formats and say what they leave out (Codex C4-1, C4-2, C4-3, C4-4).

C4-1: STIX 2.1 created / modified need millisecond precision; they had seconds.
C4-2: a MISP Attribute timestamp is Unix epoch seconds; it was ISO text.
C4-3: YARA referenced $url_* when every URL was skipped (undefined string set,
      rejected by YARA), and a command line with a newline broke its literal.
C4-4: STIX wrote no pattern for user accounts or file paths, which the guide
      promises, and said nothing about what it left out.  Also: a backslash
      (DOMAIN\\user, C:\\path) must be escaped in a STIX pattern.
Synthetic values only.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def e(v, score=0):
    return {"value": v, "count": 1, "score": score}


IOCS = {
    "ipv4": [e("10.0.0.5")], "domains": [e("evil.example")],
    "users": [e("CORP\\alice"), e("o'brien")],
    "filepaths": [e("C:\\Users\\Public\\x.exe")],
    "registry": [e("HKLM\\Software\\Run\\x")],
    "commandlines": [e('cmd /c "a\nb"', score=90)],
    "processes": [e("x.exe")], "dlls": [e("evil.dll")],
    "services": [e("svc1"), e("svc2")], "named_pipes": [e("\\\\.\\pipe\\p")],
    "tasks": [], "shares": [],
    "urls": [e("http://example/" + "a" * 300)],          # only a URL longer than YARA's 200 limit
    "summary": {}, "correlation": {},
}


def main() -> int:
    from evtx_tool.output import ioc_formats as F
    tmp = tempfile.mkdtemp(prefix="iocfmt_")
    try:
        p = os.path.join(tmp, "s.json")
        skipped = {}
        try:
            n = F.export_stix(IOCS, p, skipped=skipped)
        except TypeError:                                   # pre-fix signature
            n = F.export_stix(IOCS, p)
        b = json.load(open(p, encoding="utf-8"))
        objs = b["objects"]
        ms = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3,}Z$")
        bad = [o["id"] for o in objs for k in ("created", "modified") if not ms.match(o[k])]
        check("STIX created / modified have millisecond precision", objs and not bad, f"{len(bad)} bad")
        pats = [o["pattern"] for o in objs]
        check("STIX: user accounts are indicators, backslash and quote escaped",
              "[user-account:account_login = 'CORP\\\\alice']" in pats
              and "[user-account:account_login = 'o\\'brien']" in pats, str([x for x in pats if "user" in x]))
        check("STIX: file paths are indicators (name and directory)",
              any("file:name = 'x.exe'" in x and "parent_directory_ref.path = 'C:\\\\Users\\\\Public'" in x
                  for x in pats), str([x for x in pats if "parent_directory" in x]))
        check("STIX: registry keys and command lines are indicators",
              any(x.startswith("[windows-registry-key:key = ") for x in pats)
              and any(x.startswith("[process:command_line = ") for x in pats))
        check("STIX says which values it could not represent, with counts",
              skipped == {"services": 2, "named_pipes": 1}, str(skipped))

        p = os.path.join(tmp, "m.json")
        F.export_misp(IOCS, p)
        attrs = json.load(open(p, encoding="utf-8"))["Event"]["Attribute"]
        now = time.time()
        badts = [a["timestamp"] for a in attrs if not (str(a["timestamp"]).isdigit()
                                                       and abs(int(a["timestamp"]) - now) < 300)]
        check("MISP Attribute timestamps are Unix epoch seconds", attrs and not badts, str(badts[:2]))

        p = os.path.join(tmp, "r.yar")
        F.export_yara(IOCS, p)
        y = open(p, encoding="utf-8").read()
        refs = set(re.findall(r"any of \(\$(\w+)_\*\)", y))
        defs = set(re.findall(r"^\s+\$(\w+)_\d+ =", y, re.M))
        check("YARA references only string sets it defines", refs <= defs, f"refs {refs}, defs {defs}")
        lits = [ln for ln in y.splitlines() if re.match(r"^\s+\$\w+ =", ln)]
        check("YARA string literals are one line each and escape the newline",
              all(ln.count('"') - ln.count('\\"') == 2 for ln in lits) and any("\\n" in ln for ln in lits),
              str([ln for ln in lits if "cmd" in ln]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
