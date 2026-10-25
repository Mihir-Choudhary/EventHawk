"""Computer Normalisation groups hosts by host identity.

It used to group by "the part before the first dot, lowercased", which:
  * missed renames: a machine's setup name and its final name (EID 6011)
    showed as two machines;
  * merged every IP-address Computer value of a /8: "10.0.0.5" and
    "10.0.0.6" both became "10".
Now one row per machine, with an Evidence column saying why its names are
grouped, and suggestions (names sharing a local log file) the analyst can
confirm or reject.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                        # noqa: E402

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def ev(comp, sf, rid, eid=4624, provider="Microsoft-Windows-Security-Auditing", data=None,
       ts="2022-02-07T10:00:00.000000Z"):
    return {"event_id": eid, "computer": comp, "source_file": sf, "record_id": rid,
            "timestamp": ts, "provider": provider, "channel": "System", "level": 4,
            "level_name": "Information", "event_data": data or {}}


def events():
    out, rid = [], 0
    for comp, sf, n in (("WS01", r"C:\c\System.evtx", 3), ("ws01.corp.local", r"C:\c\Security.evtx", 2),
                        ("OLD-NAME", r"C:\c\Setup.evtx", 2), ("10.0.0.5", r"C:\c\a.evtx", 2),
                        ("10.0.0.6", r"C:\c\b.evtx", 1), ("HOSTA", r"C:\c\Shared.evtx", 2),
                        ("HOSTB", r"C:\c\Shared.evtx", 1)):
        for _ in range(n):
            rid += 1
            out.append(ev(comp, sf, rid))
    out.append(ev("WS01", r"C:\c\System.evtx", 999, eid=6011, provider="EventLog",
                  data={"Data": {"#text": ["OLD-NAME", "WS01"]}}, ts="2022-02-07T09:00:00.000000Z"))
    return out


def main() -> int:
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    evs = events()
    w._events = evs
    w._event_model.set_events(evs)
    w._on_show_computer_norm()
    dlg = w._computer_norm_dlg
    rows = list(dlg._all_rows)

    def row_with(name):
        return next((r for r in rows if name in r["variants"]), None)

    print("=== one row per machine ===")
    r = row_with("WS01")
    check("WS01, its FQDN and its old name are one row",
          r is not None and set(r["variants"]) == {"WS01", "ws01.corp.local", "OLD-NAME"},
          str(r and r["variants"]))
    ev_txt = (r or {}).get("evidence", "")
    check("its evidence names the rename", "rename at" in ev_txt, ev_txt)
    check("...and the domain suffix", "domain suffix" in ev_txt, ev_txt)
    check("the Evidence column is shown", "Evidence" in dlg._HEADERS, str(dlg._HEADERS))

    print("\n=== IP addresses kept whole ===")
    a, b = row_with("10.0.0.5"), row_with("10.0.0.6")
    check("10.0.0.5 and 10.0.0.6 are two rows", a is not None and b is not None and a is not b,
          str([r["variants"] for r in rows]))

    print("\n=== filter to this computer ===")
    dlg._on_filter_fn(list(r["variants"]) if r else [])
    want = sum(1 for e in evs if e["computer"] in {"WS01", "ws01.corp.local", "OLD-NAME"})
    check("the filter shows exactly the machine's events",
          w._proxy_model.rowCount() == want, f"{w._proxy_model.rowCount()} vs {want}")

    print("\n=== confirm / reject a suggestion ===")
    ha = row_with("HOSTA")
    sugg = (ha or {}).get("suggestions") or []
    check("HOSTA carries a shared-file suggestion",
          any(l.kind == "same_file" for l in sugg), str(sugg))
    confirm = getattr(dlg, "_confirm_link", None)
    reject = getattr(dlg, "_reject_link", None)
    if confirm and reject and sugg:
        confirm(sugg[0])
        merged = next((r for r in dlg._all_rows if "HOSTA" in r["variants"]), {})
        check("confirming merges HOSTA and HOSTB", set(merged.get("variants", [])) == {"HOSTA", "HOSTB"},
              str(merged.get("variants")))
        reject(sugg[0])
        split = next((r for r in dlg._all_rows if "HOSTA" in r["variants"]), {})
        check("rejecting splits them again", split.get("variants") == ["HOSTA"],
              str(split.get("variants")))
    else:
        check("confirm / reject actions exist", False)
    dlg.close()
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
