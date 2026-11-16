"""Count and progress signals carry numbers above 2,147,483,647.

Gemini audit 12-08 (Medium): Juggernaut's count and progress signals were
declared Signal(int), a 32-bit C int in Qt: a count above 2,147,483,647
raised OverflowError (or wrapped), on the very datasets Juggernaut is for.

Expected: 3,000,000,000 arrives unchanged through the parse-progress and
count signals (emitted), and no other count/progress signal of the
Juggernaut workers is declared with a 32-bit int.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BIG = 3_000_000_000


def main() -> int:
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.heavyweight_worker import HeavyweightParseWorker
    from evtx_tool.gui.system_activity_dialog import SystemActivityJMFetchWorker
    objs = [HeavyweightParseWorker([], None), mw._WifiJMFetchWorker("x"), SystemActivityJMFetchWorker("x")]
    cases = [("Juggernaut parse progress", objs[0].progress, (1, 2, BIG, 1.0), 2),
             ("WiFi load count", objs[1].counted, (BIG,), 0),
             ("System Activity load count", objs[2].counted, (BIG,), 0)]
    ok, n = 0, 0
    for name, sig, args, idx in cases:
        got = []
        sig.connect(lambda *a: got.append(a))
        try:
            sig.emit(*args)
            good = bool(got) and got[0][idx] == BIG
            err = "" if good else str(got)
        except Exception as exc:
            good, err = False, f"{type(exc).__name__}: {exc}"
        ok += good
        n += 1
        print(f"  {'PASS' if good else 'FAIL'}  {name} carries {BIG:,}  -- {err}")
    import inspect
    src = inspect.getsource(mw)
    bad = [ln.strip() for ln in src.splitlines()
           if ("counted" in ln or "progress" in ln or "finished_ok" in ln) and "= Signal(" in ln
           and "int" in [a.strip() for a in ln.split("Signal(", 1)[1].split(")", 1)[0].split(",")]
           and "sortRequested" not in ln and "filterApplied" not in ln]
    n += 1
    ok += not bad
    print(f"  {'PASS' if not bad else 'FAIL'}  no Juggernaut count/progress signal is a 32-bit int  -- {bad}")
    print(f"{ok}/{n} checks passed")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
