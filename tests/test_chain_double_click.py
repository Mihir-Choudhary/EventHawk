"""Double-clicking an attack chain opens its events, as the right-click action does.

Gemini audit 14-02 / 5-12 / 7-15 (High / Low / Medium): _on_chain_double_click,
connected to the chains tree's double-click, built a list of event IDs and
did nothing with it, so double-clicking a chain had no effect.

Expected: double-clicking a chain item opens a chain tab holding exactly the
chain's two events.  Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_around_review_fixes import _Item                          # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    m = T.Mode(mw, False)
    evs = T.dataset()
    m.load(w, evs)
    chain = {"rule_name": "probe", "severity": "high", "events": [dict(evs[5]), dict(evs[9])]}
    before = [k for k in w._file_tabs if k.startswith("__chain__")]
    w._on_chain_double_click(_Item(chain), 0)
    T.pump(100)
    after = [k for k in w._file_tabs if k.startswith("__chain__")]
    new = [k for k in after if k not in before]
    n = w._file_tabs[new[0]].proxy.rowCount() if new else -1
    check("double-clicking a chain opens a tab with its 2 events", len(new) == 1 and n == 2, f"{len(new)} tab(s), {n} rows")
    T.teardown(w, False, m)
    k = sum(ok for _, ok, _ in CHECKS)
    print(f"{k}/{len(CHECKS)} checks passed")
    return 0 if k == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
