"""Tab-per-file view: readable file list, real column widths, quiet close buttons.

  * The file list shows short log names ("PowerShell / Operational") -- the
    long Microsoft-Windows-...%4... file names were cut off where they differ;
    the full path stays the item's data and tooltip.
  * A per-file tab's table has the default column widths.  Its model is
    detached and re-attached while loading, which reset the header and left
    every column at Qt's 100 px (a wide # column, a clipped Timestamp).
  * Tab close buttons are the shared quiet button (icon, tooltip).

Synthetic data only.
Run: QT_QPA_PLATFORM=offscreen python tests/test_tab_per_file_layout.py
"""
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


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841
    import evtx_tool.gui.main_window as mw

    print("=== short log names ===")
    for path, want in (
        (r"C:\l\Microsoft-Windows-PowerShell%4Operational.evtx", "PowerShell / Operational"),
        (r"C:\l\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
         "TerminalServices-LocalSessionManager / Operational"),
        (r"C:\l\Security.evtx", "Security"),
        (r"C:\l\Windows PowerShell.evtx", "Windows PowerShell"),
        (r"C:\l\Microsoft-Windows-.evtx", "Microsoft-Windows-"),
        ("/x/Kaspersky Event Log.EVTX", "Kaspersky Event Log"),
    ):
        got = mw._short_log_name(path)
        check(f"{os.path.basename(path)!r} -> {want!r}", got == want, repr(got))

    print("\n=== per-file tab ===")
    sec = r"C:\s\Microsoft-Windows-PowerShell%4Operational.evtx"
    evs = [T.ev(sec, i + 1, "HOST", T.T0 + timedelta(seconds=i), 4104) for i in range(5)]
    w = mw.MainWindow()
    w._per_file_data[sec] = {"events": evs, "search_cache": None}
    st = w._create_file_tab(sec)
    check("the tab was created", st is not None)
    tbl = st.table
    for col in (0, 3, 5):
        want = w._DEFAULT_COL_WIDTHS[col]
        check(f"column {col} has its default width ({want} px), not Qt's 100",
              tbl.columnWidth(col) == want, str(tbl.columnWidth(col)))
    bar = w._events_tab_widget.tabBar()
    idx = w._events_tab_widget.indexOf(tbl)
    btn = bar.tabButton(idx, bar.ButtonPosition.RightSide)
    check("its close button is the quiet shared one",
          btn is not None and btn.text() == "" and btn.toolTip() == "Close this tab"
          and not btn.icon().isNull(), f"text={btn.text()!r}" if btn else "none")
    btn.click(); T.pump(100)
    check("and it closes the tab", w._events_tab_widget.indexOf(tbl) < 0)

    print("\n=== file list: counts and the empty-logs group ===")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QTreeWidgetItem
    secl = r"C:\s\Security.evtx"
    e1 = r"C:\s\Microsoft-Windows-Bits-Client%4Operational.evtx"
    e2 = r"C:\s\HardwareEvents.evtx"
    w._per_file_data = {
        sec: {"events": evs, "search_cache": None},
        secl: {"events": evs[:3], "search_cache": None},
        e1: {"events": [], "search_cache": None},
        e2: {"events": [], "search_cache": None},
    }
    w._populate_file_tree()
    tree = w._file_tree
    tops = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]
    texts = [f"{t.text(0)} ({t.text(1)})" for t in tops]
    check("All Events shows the total", texts[0] == "All Events (8)", texts[0])
    check("each log with events shows its count (own right-aligned column)",
          "PowerShell / Operational (5)" in texts and "Security (3)" in texts
          and bool(tops[1].textAlignment(1) & Qt.AlignmentFlag.AlignRight), str(texts))
    grp = tops[-1]
    check("empty logs are grouped last, with their number",
          texts[-1] == "Empty logs (2)" and grp.childCount() == 2, texts[-1])
    check("...collapsed, so they take one line", not grp.isExpanded())
    check("empty logs are not listed among the others",
          not any("Bits-Client" in t or "HardwareEvents" in t for t in texts[:-1]), str(texts))
    w._on_tree_item_clicked(grp, 0)
    check("clicking the group shows the empty logs", grp.isExpanded())
    w._on_tree_item_clicked(grp, 0)
    check("clicking again hides them", not grp.isExpanded())
    child = grp.child(0)
    check("an empty log keeps its full path as tooltip",
          child.toolTip(0).startswith("C:\\s\\") and "No events" in child.toolTip(0), child.toolTip(0))
    w._on_tree_item_clicked(child, 0); T.pump(100)
    check("Normal mode: an empty log still opens (an empty tab)",
          child.data(0, Qt.ItemDataRole.UserRole) in w._file_tabs)

    pivot = QTreeWidgetItem(["⏱ around"])
    pivot.setData(0, Qt.ItemDataRole.UserRole, "__around__x")
    w._add_tree_entry(pivot)
    check("a pivot tab's entry goes above the Empty logs group",
          tree.indexOfTopLevelItem(pivot) == tree.topLevelItemCount() - 2)

    w._remove_loaded_file(e2); T.pump(50)
    grp = tree.topLevelItem(tree.topLevelItemCount() - 1)
    check("removing an empty log updates the group", grp.text(1) == "1", grp.text(1))

    w._fill_file_tree({sec: 5, e1: 0}, empty_openable=False)
    g2 = tree.topLevelItem(tree.topLevelItemCount() - 1)
    check("Juggernaut Mode: an empty log's entry opens nothing (no rows to show)",
          g2.child(0).data(0, Qt.ItemDataRole.UserRole) is None)

    w.close(); T.pump(100)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
