"""Several applied profiles: an event must match ONE profile as a whole (user-approved fix, 2026-11-07).

build_combined_filter pooled every ticked profile's Event IDs and every
profile's sources, so an event passed with one profile's ID and another
profile's source.  Real corpus: Boot and Shutdown (IDs 12, 13 from
Kernel-General) ticked with Process Creation (Sysmon) showed 2,866,916 Sysmon
registry events (Sysmon 12/13), and 7,568 unrelated System events.
docs/14-profiles.md already promised "an event matching any of the profiles
passes".

Expected, in every evaluator (core passes_filter and compile_filter - parse
and CLI -, the Normal view proxy, Juggernaut SQL):
  * applied profiles combine with OR, each profile's own IDs/sources/channels
    with AND;
  * one profile alone behaves as before;
  * a base (Advanced Filter) restriction still applies on top (AND);
  * a profile with no IDs/sources/channels passes everything.
The oracle is computed here, independently of the product.  Synthetic events only.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


SOURCES = [("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational"),
           ("Microsoft-Windows-Kernel-General", "System"),
           ("Microsoft-Windows-Security-Auditing", "Security"),
           ("SecurityCenter", "Application"),
           ("Microsoft-Windows-Wininit", "System"),
           ("Vendor_App%Svc", "Application"), ("VendorXAppYSvc", "Application")]
EIDS = [1, 3, 12, 13, 4624, 4688, 6005]

BOOT = {"name": "Boot", "event_ids": [12, 13], "sources": ["Microsoft-Windows-Kernel-General"]}
PROC = {"name": "Proc", "event_ids": [1, 4688],
        "sources": ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing"]}
CHAN = {"name": "Chan", "event_ids": [6005], "channels": ["System"]}
ALL = {"name": "All", "event_ids": []}
LIT = {"name": "Literal", "sources": ["Vendor_App%"]}


def events():
    out, n = [], 0
    for prov, chan in SOURCES:
        for eid in EIDS:
            n += 1
            out.append({"event_id": eid, "provider": prov, "channel": chan, "computer": "WS01",
                        "level": 4, "level_name": "Information", "task": 0,
                        "timestamp": f"2026-02-11T13:00:{n % 60:02d}.000000Z", "record_id": n,
                        "source_file": "x.evtx", "user_id": "", "keywords": "",
                        "event_data": {}})
    return out


def one(ev, p):
    """Independent oracle: one profile = AND of its non-empty fields."""
    if p.get("event_ids") and ev["event_id"] not in p["event_ids"]:
        return False
    prov, chan = ev["provider"].lower(), ev["channel"].lower()
    if p.get("sources") and not any(s.lower() in prov or s.lower() in chan for s in p["sources"]):
        return False
    if p.get("channels") and not any(c.lower() in chan for c in p["channels"]):
        return False
    return True


def main() -> int:
    import duckdb
    from evtx_tool.core.filters import (empty_filter, build_combined_filter, passes_filter,
                                        compile_filter)
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel

    evs = events()
    model = EventTableModel(); model.set_events(evs)
    proxy = EventFilterProxyModel(); proxy.setSourceModel(model)
    con = duckdb.connect()
    con.execute("create table t (record_id bigint, event_id bigint, provider varchar, channel varchar)")
    con.executemany("insert into t values (?, ?, ?, ?)",
                    [(e["record_id"], e["event_id"], e["provider"], e["channel"]) for e in evs])

    def evaluate(fc):
        core = {e["record_id"] for e in evs if passes_filter(e, fc)}
        comp = compile_filter(fc)
        compiled = {e["record_id"] for e in evs if comp(e)}
        proxy.set_advanced_filter(fc)
        view = {model.event_at(proxy.mapToSource(proxy.index(r, 0)).row())["record_id"]
                for r in range(proxy.rowCount())} if hasattr(model, "event_at") else None
        if view is None:
            view = {model._events[proxy.mapToSource(proxy.index(r, 0)).row()]["record_id"]
                    for r in range(proxy.rowCount())}
        where, params = filter_config_to_sql(fc)
        sql = {r[0] for r in con.execute(f"select record_id from t where {where}", params).fetchall()}
        return {"passes_filter": core, "compile_filter": compiled, "Normal view": view, "Juggernaut SQL": sql}

    cases = [
        ("Boot + Process ticked together", [BOOT, PROC], None,
         lambda e: one(e, BOOT) or one(e, PROC)),
        ("Boot + a channel-only profile", [BOOT, CHAN], None,
         lambda e: one(e, BOOT) or one(e, CHAN)),
        ("one profile alone (unchanged)", [PROC], None, lambda e: one(e, PROC)),
        ("Advanced Filter (ID 12 or 1) still applies on top", [BOOT, PROC], {"event_ids": [12, 1]},
         lambda e: e["event_id"] in (12, 1) and (one(e, BOOT) or one(e, PROC))),
        ("a profile with no IDs or sources passes everything", [BOOT, ALL], None, lambda e: True),
        ("a source with _ and % matches literally", [BOOT, LIT], None,
         lambda e: one(e, BOOT) or one(e, LIT)),
    ]
    for label, profiles, base, oracle in cases:
        bf = empty_filter()
        if base:
            bf.update(base)
        fc = build_combined_filter(bf, profiles)
        want = {e["record_id"] for e in evs if oracle(e)}
        for path, got in evaluate(fc).items():
            check(f"{label}: {path}", got == want,
                  f"{len(got)} vs {len(want)} expected; extra {len(got - want)}, missing {len(want - got)}")

    # Codex CK7E-1: a filter that already holds profiles (a CLI --save-filter
    # file, loaded with --filter-file) plus another profile: the saved profile
    # restriction must still apply (AND), not be replaced.
    import json as _json
    from evtx_tool.core.filters import filter_from_dict
    saved = filter_from_dict(_json.loads(_json.dumps(build_combined_filter(empty_filter(), [PROC]))))
    for label, base, add, oracle in (
            ("saved Process filter + Boot profile", saved, [BOOT], lambda e: one(e, PROC) and one(e, BOOT)),
            ("saved Process filter + Process profile again", saved, [PROC], lambda e: one(e, PROC)),
            ("saved Process filter + saved again + Chan", build_combined_filter(saved, [PROC]), [CHAN],
             lambda e: one(e, PROC) and one(e, CHAN))):
        fc = build_combined_filter(base, add)
        want = {e["record_id"] for e in evs if oracle(e)}
        for path, got in evaluate(fc).items():
            check(f"{label}: {path}", got == want,
                  f"{len(got)} vs {len(want)} expected; extra {len(got - want)}, missing {len(want - got)}")
    # A non-vacuous intersection: one saved profile AND another that overlaps it.
    P12 = {"event_ids": [1, 12], "sources": ["Microsoft-Windows-Sysmon"]}
    P13 = {"event_ids": [12, 13], "sources": ["Microsoft-Windows-Sysmon"]}
    fc = build_combined_filter(build_combined_filter(empty_filter(), [P12]), [P13])
    want = {e["record_id"] for e in evs if one(e, P12) and one(e, P13)}
    for path, got in evaluate(fc).items():
        check(f"saved (1, 12) + profile (12, 13) keeps only 12: {path}", got == want and len(want) == 1,
              f"{len(got)} vs {len(want)} expected")

    proxy.set_advanced_filter(None)
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
