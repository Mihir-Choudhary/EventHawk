"""Parsing again after a Juggernaut load, and the Chains tab.

  A. Clearing results always puts the table back on the normal model: the
     normal parse path cleaned Juggernaut up first and the table kept the
     released model, showing numbered blank rows under "0 events".
  B. An analysis run that is no longer current cannot fill the tabs: a run
     stopped by a new parse delivered its chains while other logs loaded.
  C. Chains: an expanded event row puts each value under its heading (the
     time sat under Events, the event ID under Severity), times follow the
     display zone, the description spans the row.
  D. The analysis scope selector sits in the tab bar's corner.

Run: QT_QPA_PLATFORM=offscreen python tests/test_reparse_ux.py
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import test_around_pivot as T
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.analysis.analysis_runner import AnalysisRunner
    from evtx_tool.gui.models import apply_tz
    w = mw.MainWindow()
    w.resize(1366, 768)
    w.show()
    T.pump(200)

    print("=== A. table after a Juggernaut load is cleared ===")
    evs = [T.ev("Security.evtx", i, "WS1", f"2025-06-29T12:00:{i:02d}.000000Z") for i in range(1, 6)]
    T.Mode(w, True).load(w, evs)
    w._table.setModel(w._hw_model)
    T.pump(200)
    check("(setup) the table shows the Juggernaut model", w._table.model() is w._hw_model)
    w._cleanup_juggernaut()          # what the normal parse path does first
    w._clear_results()
    T.pump(100)
    check("clearing results puts the table back on the normal model",
          w._table.model() is w._proxy_model, type(w._table.model()).__name__)
    check("...with no leftover rows", w._table.model().rowCount() == 0, str(w._table.model().rowCount()))

    print("\n=== B. results of an old analysis run are ignored ===")
    old, cur = AnalysisRunner(parent=w), AnalysisRunner(parent=w)
    for r in (old, cur):
        r.finished.connect(w._on_analysis_finished)
    w._analysis_runner = cur
    chain = {"severity": "high", "rule_name": "Old rule", "computers": ["WS1"], "events": [],
             "first_event_ts": "2025-06-29T12:00:00Z"}
    old.finished.emit({}, [chain], {})
    T.pump(100)
    check("a stopped run's chains do not reach the tab", w._chains == [], str(len(w._chains)))
    cur.finished.emit({}, [chain], {})
    T.pump(100)
    check("the current run's chains do", len(w._chains) == 1)
    w._analysis_runner = None

    print("\n=== C. Chains rows ===")
    ts = "2025-06-29T12:00:03.250000Z"
    w._chains = [{"severity": "high", "rule_name": "Suspicious spawn", "computers": ["WS1"],
                  "description": "A long description of why this chain matters " * 3,
                  "first_event_ts": ts,
                  "events": [{"event_id": 4688, "timestamp": ts, "computer": "WS1", "event_record_id": 77}]}]
    w._refresh_chains_tab()
    top = w._tree_chains.topLevelItem(0)
    check("First Seen in the display zone, exact UTC on hover",
          top.text(4) == apply_tz(ts) and top.toolTip(4) == f"UTC {ts}", top.text(4))
    check("event rows are not built until the chain is expanded", top.childCount() == 1, str(top.childCount()))
    w._tree_chains.expandItem(top)
    T.pump(50)
    desc, evrow = top.child(0), top.child(1)
    check("the description spans the whole row", desc.isFirstColumnSpanned())
    check("an event row: event and record under Rule, nothing under Severity",
          evrow.text(0) == "" and evrow.text(1).startswith("Event 4688") and "record 77" in evrow.text(1),
          f"{evrow.text(0)!r} {evrow.text(1)!r}")
    check("...computer under Computers, nothing under Events, time under First Seen",
          evrow.text(2) == "WS1" and evrow.text(3) == "" and evrow.text(4) == apply_tz(ts),
          f"{evrow.text(2)!r} {evrow.text(3)!r} {evrow.text(4)!r}")

    print("\n=== C2. empty tabs say what happened ===")
    w._chains, w._chains_ran = [], True
    w._refresh_chains_tab()
    check("correlation ran and found nothing: says so",
          w._lbl_chains_summary.text() == "No attack chains found in these events.", w._lbl_chains_summary.text())
    w._chains_ran = False
    w._refresh_chains_tab()
    check("correlation not run: says how to run it",
          "not run" in w._lbl_chains_summary.text() and "Correlation Engine" in w._lbl_chains_summary.text(),
          w._lbl_chains_summary.text())

    class _Busy:
        def isRunning(self):
            return True
    w._worker, w._parse_state = _Busy(), (8, 417, 1762, 191.0, 12.0)
    icon_, title, body = w._main_table_empty_hint()
    check("while parsing the events area shows the progress",
          title == "Parsing 8 of 417 files (1%)" and "1,762 events so far" in body, f"{title} | {body[:60]}")
    w._worker = None

    print("\n=== D. analysis scope selector ===")
    check("it sits in the analysis tab bar's corner",
          w._analysis_tabs.cornerWidget(Qt.Corner.TopRightCorner) is w._scope_row_widget)
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
