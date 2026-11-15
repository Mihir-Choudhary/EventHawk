"""A Sysmon IMPHASH is not extracted as a file MD5.

Gemini audit 7-09 (High): extract_iocs stripped every "ALGO=" prefix from
Sysmon's Hashes field and sorted the rest by length, so IMPHASH (32 hex,
a digest of the PE import table) became an "MD5" IOC, and STIX exported it
as file:hashes.'MD5'.

Expected: Hashes "SHA256=<x>,IMPHASH=<y>" gives sha256 [x] and no md5;
"MD5=<z>" still gives md5 [z].  Synthetic event.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def vals(iocs, k):
    return [e.get("value") if isinstance(e, dict) else e for e in (iocs.get(k) or [])]


def main() -> int:
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    imp = "11223344556677889900aabbccddeeff"
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    ev = lambda rid, h: {"record_id": rid, "event_id": 1, "timestamp": "2026-01-01T00:00:00.000000Z",
                         "computer": "H", "channel": "Microsoft-Windows-Sysmon/Operational",
                         "provider": "Microsoft-Windows-Sysmon", "source_file": "s.evtx",
                         "event_data": {"Image": r"C:\Windows\System32\notepad.exe", "Hashes": h}}
    i = extract_iocs([ev(1, f"SHA256={sha},IMPHASH={imp}")])
    check("the SHA-256 is extracted", vals(i, "sha256") == [sha], str(vals(i, "sha256")))
    check("the IMPHASH is not an MD5", imp not in vals(i, "md5"), str(vals(i, "md5")))
    i = extract_iocs([ev(2, f"MD5={md5}")])
    check("a real MD5 is still extracted", vals(i, "md5") == [md5], str(vals(i, "md5")))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
