"""IOC exports: YARA hashes are lowercase hex; STIX literals escape line breaks.

Gemini audit 6-09 (Medium): export_yara wrote hashes as given; YARA's hash
functions return lowercase hex, so an uppercase digest never matched, and a
value with a quote broke the rule.
Gemini audit 6-17 (Low): _stix_lit left CR / LF / TAB raw inside a STIX
pattern string literal (invalid grammar for a multi-line command line), and
export_yara took the first 100 URLs BEFORE dropping over-long ones, so 100
long URLs crowded out every valid one.

Expected: an uppercase SHA-256 is written lowercase; a non-hex value is not
written as a hash; a STIX pattern for a two-line command line has no raw
newline; a valid URL after 100 over-long ones is in the YARA rule.
Synthetic values.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.output.ioc_formats import export_yara, export_stix
    d = tempfile.mkdtemp(prefix="iocg_")
    try:
        up = "AB" * 32
        iocs = {"sha256": [{"value": up}, {"value": 'zz"bad'}],
                "urls": [{"value": "http://x/" + "a" * 300} for _ in range(100)] + [{"value": "http://good.example/p"}],
                "commandlines": [{"value": "cmd.exe /c a\r\nb\tc", "score": 90}]}
        y = os.path.join(d, "r.yar")
        export_yara(iocs, y)
        rule = open(y, encoding="utf-8").read()
        check("an uppercase SHA-256 is written lowercase", up.lower() in rule and up not in rule)
        check("a non-hex value is not written as a hash", 'zz"bad' not in rule and 'zz\\"bad' not in rule)
        check("a valid URL after 100 over-long ones is in the rule", "good.example" in rule)
        s = os.path.join(d, "s.json")
        export_stix(iocs, s)
        pats = [o.get("pattern", "") for o in json.load(open(s, encoding="utf-8")).get("objects", [])
                if o.get("type") == "indicator"]
        cmd = [p for p in pats if "cmd.exe" in p]
        check("a two-line command line has no raw CR/LF/TAB in its STIX pattern",
              cmd and not any(c in cmd[0] for c in "\r\n\t"), repr(cmd[:1])[:120])
    finally:
        shutil.rmtree(d, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
