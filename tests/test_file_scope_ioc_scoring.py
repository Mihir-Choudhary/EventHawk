"""'This File' IOCs are scored and correlated like the collection's.

Gemini audit 7-15 (Medium), part 2: in the separate view with Analysis scope
"This File", the IOC tab extracted the file's IOCs but did not score or
correlate them (no co-occurrence pairs, scores only where the collection
had the same value).

Expected: the file-scoped IOCs carry a "correlation" result, and the encoded
PowerShell command line has a score > 50.  Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
FA = r"C:\c\hostA\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    cmd = "powershell.exe -NoProfile -EncodedCommand dGVzdA=="
    e = T.ev(FA, 1, "HOST-A", T.T0, 4688, data={"CommandLine": cmd, "NewProcessName": r"C:\x\powershell.exe",
                                               "IpAddress": "198.51.100.4"})
    w = mw.MainWindow()
    m = T.Mode(mw, False)
    m.load(w, [e])
    w._iocs = {"summary": {}}            # the collection ran extraction (no matches needed)
    w._view_mode = "separate"
    w._per_file_data = {FA: {"events": [e], "search_cache": []}}
    w._create_file_tab(FA)
    w._active_file_tab = FA
    w._analysis_scope = "file"
    iocs = w._scoped_iocs() or {}
    pairs = ((iocs.get("correlation") or {}).get("pairs") or []) if isinstance(iocs.get("correlation"), dict) else []
    check("the file-scoped IOCs have co-occurrence pairs", len(pairs) > 0, str(len(pairs)))
    sc = [x.get("score", 0) for x in iocs.get("commandlines") or [] if x.get("value") == cmd]
    check("the encoded command line is scored (> 50)", sc and sc[0] > 50, str(sc))
    T.teardown(w, False, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
