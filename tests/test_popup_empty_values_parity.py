"""Column popups offer "(empty)" alike in Normal and Juggernaut (Gemini audit 5-10 part 2).

Juggernaut's popup counts an empty field ('' passes "IS NOT NULL") and offers
it as "(empty)"; Normal mode's popup left it out.  Events with a blank
Computer, Channel or User could therefore be picked in one mode and not the
other, and Normal's counts did not add up to the events shown.  Expected:
both popups list the same values with the same counts for every column here,
'' included, and picking '' in Normal keeps exactly those events.
Synthetic events only.
"""
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_jm_export_text_filter import write_jm                     # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events():
    out = []
    rows = [("Security", "PC-1", "alice"), ("", "PC-1", ""), ("Security", "", "bob"),
            ("System", "PC-2", ""), ("", "", "alice"), ("Security", "PC-1", "alice")]
    for n, (ch, comp, user) in enumerate(rows, 1):
        out.append({"event_id": 4624, "level": 4, "level_name": "Information", "provider": "P",
                    "channel": ch, "computer": comp, "user_id": user, "record_id": n,
                    "source_file": r"C:\a\s.evtx", "timestamp": f"2024-01-01T00:00:{n:02d}.000000Z",
                    "event_data": {"N": str(n)}})
    return out


def counts(worker):
    out = []
    worker.finished.connect(lambda v: out.append(v))
    worker.run()
    v = out[0] if out else None
    items = getattr(v, "items", v) if v is not None else []
    items = items() if callable(items) else items
    return dict(items or [])


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.jm_col_worker import NormalColValueWorker, ColValueWorker
    evs = events()
    table = write_jm(evs, tempfile.mkdtemp(prefix="popempty_"))
    for key in ("channel", "computer"):
        nor = counts(NormalColValueWorker(evs, key))
        jm = counts(ColValueWorker(table, key))
        check(f"{key}: Normal and Juggernaut popups list the same values and counts", nor == jm,
              f"Normal {nor} | JM {jm}")
        check(f"{key}: '' is offered, counted once per blank event",
              nor.get("") == sum(1 for e in evs if e[key] == ""), str(nor.get("")))
        check(f"{key}: the counts add up to the events", sum(nor.values()) == len(evs), str(sum(nor.values())))
    nor = counts(NormalColValueWorker(evs, "user_id"))
    check("user_id: '' is offered in Normal", nor.get("") == 2, str(nor))

    # Picking "(empty)" in the Normal window keeps exactly the blank events.
    import test_around_pivot as T
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    m = T.Mode(mw, False)
    m.load(w, evs)
    T.pump(50)
    idx = next(i for i, k in mw.ColumnFilterPopup.FILTERABLE.items() if k == "computer")
    w._on_col_filter_applied(idx, "include", [""])
    T.pump(50)
    shown = sorted(w._proxy_model.get_source_event(r)["record_id"] for r in range(w._proxy_model.rowCount()))
    want = sorted(e["record_id"] for e in evs if e["computer"] == "")
    check("picking (empty) on Computer keeps exactly the blank-computer events", shown == want, f"{shown} vs {want}")
    T.teardown(w, False, m)
    app.processEvents()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
