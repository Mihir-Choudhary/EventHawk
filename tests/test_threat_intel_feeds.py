"""Offline threat-intel feeds load what they hold, and VirusTotal counts what it checked.

Gemini audit 7-08 (High):
1. an IPv4 in a 2-column CSV was filed as a domain ("." tested before IPv4);
2. csv.Sniffer took the first row of a headerless CSV for a header and
   dropped it (a 1-row hash list loaded 0);
3. EventHawk's own 6-column IOC CSV (type,value,count,...) read "count" as
   the verdict;
4. a TXT line with a process path was filed as a domain;
5. a STIX bundle EventHawk exported with a command line loaded 0 indicators;
6. VirusTotal mode counted IOC types it cannot check as "checked".

Expected: each of those loads / counts correctly.  Synthetic feeds.
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
    from evtx_tool.analysis.threat_intel import ThreatIntelChecker
    d = tempfile.mkdtemp(prefix="ti_")
    try:
        def load(name, text):
            p = os.path.join(d, name)
            open(p, "w", encoding="utf-8").write(text)
            t = ThreatIntelChecker()
            n = t.load_offline(p)
            return t, n
        t, _ = load("a.csv", "indicator,verdict\n192.0.2.10,malicious\n")
        v = (t.check_offline("ipv4", "192.0.2.10") or {}).get("verdict")
        check("a 2-column CSV IPv4 is an IPv4", v == "malicious", str(v))
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        _, n1 = load("b.csv", sha + "\n")
        _, n3 = load("c.csv", "192.0.2.1,suspicious\n192.0.2.100,malicious\n192.0.2.101,malicious\n")
        check("headerless CSVs keep their first row", (n1, n3) == (1, 3), str((n1, n3)))
        t, _ = load("d.csv", "type,value,count,first_seen,last_seen,score\nipv4,198.51.100.7,7,,,30\n")
        v = (t.check_offline("ipv4", "198.51.100.7") or {}).get("verdict")
        check("EventHawk's 6-column IOC CSV loads (count is not a verdict)", v == "malicious", str(v))
        t, _ = load("e.txt", "C:\\Windows\\System32\\powershell.exe\n")
        v = (t.check_offline("processes", "C:\\Windows\\System32\\powershell.exe") or {}).get("verdict")
        check("a TXT process path is a process", v == "malicious", str(v))
        from evtx_tool.output.ioc_formats import export_stix
        sp = os.path.join(d, "s.json")
        export_stix({"commandlines": [{"value": "cmd.exe /c whoami", "count": 1, "score": 90}]}, sp)
        t = ThreatIntelChecker()
        n = t.load_offline(sp)
        check("a STIX bundle with a command line loads it", n == 1, str(n))
        t = ThreatIntelChecker(api_key="x")
        iocs = {"processes": [{"value": "a.exe"}], "users": [{"value": "bob"}]}
        try:
            st = t.enrich_iocs(iocs, mode="virustotal", ioc_types=["processes", "users"])
        except TypeError:
            st = t.enrich_iocs(iocs, "virustotal", ["processes", "users"])
        check("types VirusTotal cannot check are not counted as checked", (st or {}).get("checked") == 0,
              str(st))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
