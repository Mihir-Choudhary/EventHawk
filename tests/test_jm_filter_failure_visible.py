"""A Juggernaut filter that fails says so on screen; the view never poses as filtered.

Found by Codex in audit-5 (E5-05, pre-existing): a filter DuckDB cannot run
(here a regex Python accepts and DuckDB's RE2 rejects: a lookbehind) left the
view showing every event (1,840,546 instead of 0 on the corpus) and said so
only in the log ("UNRELIABLE").  Showing every event is the deliberate
fallback (hiding everything would hide evidence), but a view that looks
filtered and is not misleads.  Expected: the model reports the failure and
the window shows a warning that the table is NOT filtered, for the main
filter and for the text and field-condition phases.  Synthetic events.
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
BAD = "(?<=a)b"                     # valid in Python, not supported by DuckDB (RE2)


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    evs = [T.ev(r"C:\c\Security.evtx", i + 1, "HOST", T.T0 + timedelta(seconds=i), 4624, data={"Cmd": "ab"})
           for i in range(5)]
    for label, cfg in (
        ("text regex", {"text_search": BAD, "text_regex": True}),
        ("field-condition regex", {"conditions": [{"name": "Cmd", "operator": "regex", "value": BAD}]}),
    ):
        w = mw.MainWindow()
        m = T.Mode(mw, True)
        m.load(w, evs)
        w._table.setModel(w._hw_model)
        w._connect_jm_model_signals(w._hw_model)
        warned = []
        w._warn_blocking = lambda title, text, **k: warned.append((title, text))
        reported = []
        w._hw_model.filter_failed.connect(lambda msg: reported.append(msg))
        w._hw_model.apply_filter(cfg)
        T.wait_for(lambda: reported and warned, 30); T.pump(300)
        check(f"{label}: the model reports the failed filter", reported, str(reported[:1])[:120])
        check(f"{label}: the window warns that the table is NOT filtered",
              warned and "not filtered" in warned[0][1].lower(), str(warned[:1])[:160])
        check(f"{label}: the view still shows every event (nothing hidden)", w._hw_model.rowCount() == len(evs),
              str(w._hw_model.rowCount()))
        T.teardown(w, True, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
