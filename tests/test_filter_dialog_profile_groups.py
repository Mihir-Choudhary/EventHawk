"""Advanced Filter Load / Save keeps a saved filter's profile restrictions (Codex C2-1).

A filter saved by the CLI (--save-filter) after applying profiles stores them in
profile_groups (and profile_groups_also).  The dialog has no field for those:
Load restored only its fields and Save wrote only them, so a loaded filter
silently lost its profile restriction (real app: 143,448 events instead of 252).
Expected: Load keeps them, the dialog says so, Save writes them, reopening and
OK keep them, Clear removes them; applied profiles still AND on top.
Synthetic data only.
"""
import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


A = {"name": "A", "event_ids": [4624, 4688], "sources": ["Microsoft-Windows-Security-Auditing"]}
B = {"name": "B", "event_ids": [4688, 1], "sources": ["Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon"]}


def events():
    out, n = [], 0
    for prov in ("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon"):
        for eid in (1, 4624, 4688, 4634):
            n += 1
            out.append({"event_id": eid, "provider": prov, "channel": "Security", "record_id": n,
                        "timestamp": "2024-01-02T03:04:05Z", "event_data": {}, "computer": "PC"})
    return out


def main() -> int:
    from PySide6.QtWidgets import QFileDialog, QMessageBox
    from evtx_tool.core.filters import empty_filter, build_combined_filter, passes_filter
    from evtx_tool.gui.filter_dialog import FilterDialog
    tmp = tempfile.mkdtemp(prefix="fdpg_")
    try:
        saved = build_combined_filter(empty_filter(), [A])            # what the CLI saves
        src = os.path.join(tmp, "cli_saved.json")
        with open(src, "w", encoding="utf-8") as fh:
            json.dump(saved, fh)
        out = os.path.join(tmp, "gui_saved.json")
        QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (src, ""))
        QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out, ""))
        boxes = []
        for _n in ("information", "warning", "critical", "question"):
            setattr(QMessageBox, _n, staticmethod(lambda *a, _n=_n, **k: boxes.append((_n, a[1:3] if len(a) > 2 else a))))

        dlg = FilterDialog(metadata={}, current_filter=None)
        dlg._load_preset()
        cfg = dlg.get_filter_config()
        check("Load keeps the saved profile restriction", cfg.get("profile_groups") == saved["profile_groups"],
              str(cfg.get("profile_groups")))
        lbl = getattr(dlg, "_lbl_hidden", None)
        check("the dialog says it holds a profile restriction",
              lbl is not None and not lbl.isHidden() and "profile" in lbl.text().lower(),
              lbl.text() if lbl is not None else "no label")
        dlg._save_preset()
        check("no warning or error box was raised", not [b for b in boxes if b[0] != "information"], str(boxes))
        with open(out, encoding="utf-8") as fh:
            gui_saved = json.load(fh)
        check("Save writes it", gui_saved.get("profile_groups") == saved["profile_groups"])

        dlg2 = FilterDialog(metadata={}, current_filter=cfg)            # reopen, OK unchanged
        check("reopening and OK keep it", dlg2.get_filter_config().get("profile_groups") == saved["profile_groups"])

        evs = events()
        fc = build_combined_filter(dlg2.get_filter_config(), [B])        # a profile applied on top
        got = {e["record_id"] for e in evs if passes_filter(e, fc)}
        want = {e["record_id"] for e in evs
                if e["event_id"] in (4624, 4688) and e["provider"].endswith("Auditing")
                and e["event_id"] in (4688, 1)}
        check("applied profiles AND on top of the loaded one", got == want and len(want) == 1,
              f"{sorted(got)} vs {sorted(want)}")

        dlg2._clear_all()
        c2 = dlg2.get_filter_config()
        check("Clear removes it", not c2.get("profile_groups") and not c2.get("profile_groups_also"))
        check("after Clear the dialog no longer says so",
              getattr(dlg2, "_lbl_hidden", None) is not None and dlg2._lbl_hidden.isHidden())

        # Codex DOC-4: a CLI-saved text search is a list with a mode
        # (--search alpha --search beta --search-mode OR); Load crashed.
        txt = dict(saved, text_search=["alpha", "beta"], search_mode="OR")
        try:
            dlg4 = FilterDialog(metadata={}, current_filter=txt)
            c4 = dlg4.get_filter_config()
            ok4 = c4.get("text_search") == ["alpha", "beta"] and c4.get("search_mode") == "OR"
            shown4 = "alpha" in dlg4._lbl_hidden.text() and not dlg4._lbl_hidden.isHidden()
            dlg4._inp_text.setText("gamma")
            c5 = dlg4.get_filter_config()
            typed = c5.get("text_search") == "gamma"
            one = FilterDialog(metadata={}, current_filter=dict(saved, text_search=["solo"], search_mode="AND"))
            single = one._inp_text.text() == "solo"
        except Exception as exc:                                     # noqa: BLE001
            ok4 = shown4 = typed = single = False
            print("   ", repr(exc))
        check("a CLI-saved multi-term text search loads, is kept and shown", ok4 and shown4)
        check("typing a text search replaces it; a single saved term goes in the field", typed and single)
        also = build_combined_filter(saved, [B])                         # a file holding both sets
        dlg3 = FilterDialog(metadata={}, current_filter=also)
        c3 = dlg3.get_filter_config()
        check("profile_groups_also is kept too", c3.get("profile_groups_also") == also["profile_groups_also"]
              and c3.get("profile_groups") == also["profile_groups"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
