"""Three GUI state fixes: the "N/A" user, missing-ID labels, popup search ticks.

Gemini audit 5-09 (High): the Users picker offered "N/A" (events with no
user) but picking it filtered on the text "N/A", which no event has: 0 rows.
Gemini audit 5-05 (Medium): the Missing Record IDs report put file names into
HTML unescaped ("<unknown>" vanished, "&" broke) and two folders' same-named
logs got the same heading.
Gemini audit 5-10 (Medium): clearing a column popup's search ticked every
value, undoing what the analyst had unticked.

Expected: no "N/A" user in the Normal metadata; the report shows
"&lt;unknown&gt;" and two distinct headings for host1/Security.evtx and
host2/Security.evtx; after typing and clearing a popup search the ticks are
as before.  Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    from evtx_tool.gui.metadata import build_metadata
    base = {"event_id": 1, "level": 4, "level_name": "Information", "channel": "C", "computer": "H",
            "provider": "P", "timestamp": "2026-01-01T00:00:00.000000Z", "event_data": {}}
    evs = [dict(base, record_id=1, user_id="", source_file=""),
           dict(base, record_id=3, user_id="S-1-5-18", source_file=""),
           dict(base, record_id=1, user_id="", source_file=r"C:\host1\Security.evtx"),
           dict(base, record_id=4, user_id="", source_file=r"C:\host1\Security.evtx"),
           dict(base, record_id=1, user_id="", source_file=r"C:\host2\Security.evtx"),
           dict(base, record_id=5, user_id="", source_file=r"C:\host2\Security.evtx")]
    md = build_metadata(evs)
    users = md.get("users") or md.get("user") or {}
    check("the Users picker offers no 'N/A'", "N/A" not in users, str(dict(users)))

    import evtx_tool.gui.main_window as mw
    captured = {}
    orig = mw._MissingRecordIdDialog.__init__

    def spy(self, *a, **k):
        captured["args"] = a
        captured["kw"] = k
        orig(self, *a, **k)
    mw._MissingRecordIdDialog.__init__ = spy
    mw._MissingRecordIdDialog.exec = lambda self: 0
    w = mw.MainWindow()
    w._events = evs
    w._event_model.set_events(evs)
    w._on_identify_missing_record_ids("record_id")
    html = " ".join(str(x) for x in list(captured.get("args", ())) + list(captured.get("kw", {}).values()))
    check("the report shows '<unknown>' escaped", "&lt;unknown&gt;" in html, html[:200])
    check("two folders' Security.evtx get distinct headings",
          html.count("<b>") >= 3 and len(set(x.split("</b>")[0] for x in html.split("<b>")[1:])) >= 3, html[:300])
    w.close()

    from evtx_tool.gui.main_window import ColumnFilterPopup
    pop = ColumnFilterPopup(1, {"4624": 5, "4625": 3, "4634": 2})
    for chk in pop._checkboxes:
        if chk.property("filter_value") == "4625":
            chk.setChecked(False)
    before = sorted(str(c.property("filter_value")) for c in pop._checkboxes if c.isChecked())
    pop._filter_list("4634")
    pop._filter_list("")
    after = sorted(str(c.property("filter_value")) for c in pop._checkboxes if c.isChecked())
    check("typing and clearing a popup search keeps the ticks", before == after == ["4624", "4634"],
          f"{before} -> {after}")
    pop.close()
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
