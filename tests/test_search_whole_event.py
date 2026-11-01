"""Text search covers the whole event, the same in every mode.

User (2026-11-01): "It must search all content of each event: the System
section ..., EventData/UserData fields, the rendered description, and the raw
XML ... an IP or other IOC that appears only in a System field or a
non-description field must still be found."  Spec item 5 / R-8: the search
haystack holds every System field EventHawk keeps, every EventData/UserData
value and name, the description shown in the details pane, the semantic
labels (*_desc) and the System XML element/attribute names.  One haystack for
the Normal view, the parse-time filter (and Juggernaut, Task 8: the JM leg
below runs when EVTX_TEST_LOGS is set).  Synthetic events, except the JM leg's
counts on the real logs.
"""
import glob
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events():
    base = dict(provider="Microsoft-Windows-Kernel-General")
    out = []
    for i in range(6):
        e = T.ev(r"C:\s\System.evtx", i + 1, f"HOST-{i}", T.T0 + timedelta(seconds=i), 12, **base)
        e["keywords"] = "0x8000000000000000"
        e["event_data"] = {"Note": f"plain {i}"}
        out.append(e)
    out[0]["computer"] = "SYSMARKER-HOST"                            # System field
    out[1]["provider_guid"] = "{1A2B3C4D-0000-4444-8888-0123456789AB}"  # System attribute
    out[2]["event_data"] = {"ClientAddr": "10.66.77.88"}             # EventData value
    out[3]["event_data"] = {"ZzUnusualFieldName": "x"}               # EventData field NAME
    out[4]["event_data"] = {"EventXML": {"Param1": "USERDATAMARKER"}}  # nested UserData leaf
    out[5].update(event_id=4624, provider="Microsoft-Windows-Security-Auditing", channel="Security",
                  keywords="0x8020000000000000",
                  event_data={"LogonType": "3", "IpAddress": "10.1.2.3"})   # description + labels
    return out


def main() -> int:
    from evtx_tool.core.filters import passes_filter, _ADV_SEARCH_FIELDS
    from evtx_tool.analysis.event_descriptions import get_event_description
    import evtx_tool.gui.main_window as mw
    evs = events()
    desc = get_event_description(dict(evs[5])) or ""
    phrase = desc[:24].lower()
    cases = [
        ("a System field (Computer)", "sysmarker-host", {0}),
        ("a System attribute (Provider Guid)", "1a2b3c4d-0000", {1}),
        ("an EventData value (an IP)", "10.66.77.88", {2}),
        ("an EventData field name", "zzunusualfieldname", {3}),
        ("a nested UserData leaf", "userdatamarker", {4}),
        ("the description shown in the details pane", phrase, {5}),
        ("a semantic label (LogonType 3)", "smb / rpc", {5}),
        ("the Keywords label", "audit success", {5}),
        ("a System XML name every event has", "systemtime", set(range(6))),
        ("something no event holds", "nothing-like-this-anywhere", set()),
    ]
    check("the description used for the check exists", len(phrase) >= 10, repr(desc[:60]))
    w = mw.MainWindow()
    T.Mode(mw, False).load(w, evs)
    for label, term, want in cases:
        w._proxy_model.set_advanced_filter({"text_search": term})
        T.pump(30)
        shown = {int(w._proxy_model.get_source_event(r)["record_id"]) - 1
                 for r in range(w._proxy_model.rowCount())}
        parse = {i for i, e in enumerate(evs) if passes_filter(dict(e), {"text_search": [term]})}
        check(f"{label}: found by the view and by the parse-time filter",
              shown == want and parse == want, f"view {sorted(shown)}, parse-time {sorted(parse)}, want {sorted(want)}")
    w.close(); T.pump(50)

    # Every System field the parser keeps is searched (a new one cannot be
    # silently left out of the fixed list).
    from evtx_tool.core import parser
    rec = {"Event": {"System": {"Provider": {"#attributes": {"Name": "P"}}, "EventID": 1, "Channel": "C",
                                "Computer": "H", "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}}},
                     "EventData": {"A": "b"}}}
    keys = set(parser._extract_from_json(rec, 1, "2024-01-01T00:00:00Z", "f.evtx")) - {"event_data"}
    check("every field the parser keeps is in the search scope", keys <= set(_ADV_SEARCH_FIELDS),
          str(sorted(keys - set(_ADV_SEARCH_FIELDS))))

    rc = jm_leg()
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) and rc == 0 else 1


def jm_leg() -> int:
    """Juggernaut searches the same scope: real logs, Normal haystack vs JM SQL."""
    logs = os.environ.get("EVTX_TEST_LOGS", "")
    files = [p for p in (os.path.join(logs, n) for n in ("Security.evtx", "System.evtx")) if os.path.exists(p)]
    if not files:
        print("  (EVTX_TEST_LOGS not set -- Juggernaut leg skipped)")
        return 0
    import shutil
    import tempfile
    import duckdb
    from evtx_tool.core.parser import iter_events
    from evtx_tool.core.filters import passes_filter
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    from evtx_tool.core.heavyweight.filter_sql import text_config_to_parquet_sql
    norm = [e for f in files for e in iter_events(f)]
    tmp = tempfile.mkdtemp(prefix="jm_search_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(files)
        shards = sorted(glob.glob(os.path.join(pq, "**", "*.parquet"), recursive=True))
        con = duckdb.connect()
        for term in ("smb / rpc", "audit success", "successful logon", "systemtime", "network"):
            where, params = text_config_to_parquet_sql({"text_search": [term]})
            jm = con.execute(f"SELECT count(*) FROM read_parquet(?) WHERE {where}", [shards, *params]).fetchone()[0]
            nm = sum(1 for e in norm if passes_filter(dict(e), {"text_search": [term]}))
            check(f"JM = Normal for {term!r} on the real logs", jm == nm, f"JM {jm:,}, Normal {nm:,}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
