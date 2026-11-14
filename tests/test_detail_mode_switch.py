"""Event detail: a Full | Brief switch that shows both modes and marks the one in use.

The single "Brief" button read as the opposite state (backlog: "Brief/Full
toggle label reads as the opposite state").  Now:
  - Full and Brief are both visible, side by side, exactly one is checked;
  - Full is the default; clicking Brief shows the header and description only,
    clicking Full brings every field back;
  - clicking the checked half again does not switch it off.

Run: QT_QPA_PLATFORM=offscreen python tests/test_detail_mode_switch.py
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
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    w.resize(1366, 768)
    w.show()
    T.pump(300)
    evs = [T.ev("Security.evtx", 1, "WS1", "2025-06-29T12:00:00.000000Z", eid=4624,
                data={"TargetUserName": "alice", "LogonType": "2", "IpAddress": "10.0.0.5"}),
           T.ev("Security.evtx", 2, "WS1", "2025-06-29T12:00:01.000000Z", eid=4634, data={"TargetUserName": "alice"})]
    T.Mode(w, False).load(w, evs)
    T.pump(300)
    full, brief = w._btn_detail_full, w._btn_detail_mode
    check("both halves are shown", full.isVisible() and brief.isVisible() and full.text() == "Full"
          and brief.text() == "Brief")
    check("Full is the default and the only checked half", full.isChecked() and not brief.isChecked()
          and w._detail_full_mode)
    w._table.selectRow(0)
    T.pump(300)
    html_full = w._detail_browser.toPlainText()
    check("Full shows the event's fields", "TargetUserName" in html_full or "alice" in html_full, html_full[:120])
    brief.click()
    T.pump(300)
    html_brief = w._detail_browser.toPlainText()
    check("clicking Brief switches to Brief (only Brief checked)", brief.isChecked() and not full.isChecked()
          and not w._detail_full_mode)
    check("...and the pane gets shorter (header and description only)", len(html_brief) < len(html_full),
          f"{len(html_brief)} < {len(html_full)}")
    brief.click()
    T.pump(200)
    check("clicking the checked half again keeps it on", brief.isChecked() and not w._detail_full_mode)
    full.click()
    T.pump(300)
    check("clicking Full brings every field back", full.isChecked() and w._detail_full_mode
          and w._detail_browser.toPlainText() == html_full)
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
