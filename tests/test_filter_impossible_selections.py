"""A filter the analyst cannot have meant never silently matches every event.

Gemini audit 3-04 (High): "4630-4624" (range written high-to-low) passed
validation but parsed to an empty set, and an empty include set means "no
Event ID restriction", so every event matched; "4630-4624!4625" became "all
but 4625".  The CLI's --event-id 4630-4624 did the same.
Gemini audit 3-05 (High): unticking all 8 Event Types gave levels=[], the
same as "all ticked", so every event matched; reopening showed 8 ticked.

Expected:
- the dialog validator rejects "4630-4624";
- a high-to-low range read from a saved filter/profile is read as the range
  it names (4624..4630), never as "everything";
- the CLI refuses --event-id 4630-4624 with an error;
- the dialog refuses OK with no Event Type ticked.
Synthetic values only.
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
    from evtx_tool.core.filters import (validate_event_id_expression, parse_event_id_expression,
                                        empty_filter, compile_filter)
    check("the validator rejects a high-to-low range", validate_event_id_expression("4630-4624") == ["4630-4624"],
          repr(validate_event_id_expression("4630-4624")))
    inc, exc = parse_event_id_expression("4630-4624")
    check("a high-to-low range parses to the range it names", inc == set(range(4624, 4631)), repr(sorted(inc))[:60])
    fc = empty_filter()
    fc["event_id_expr"] = "4630-4624"
    f = compile_filter(fc)
    check("...so an unrelated event (7036) does not match", not f({"event_id": 7036, "event_data": {}}))
    inc, exc = parse_event_id_expression("4630-4624!4625")
    check("'4630-4624!4625' is the range without 4625, not 'all but 4625'",
          inc == set(range(4624, 4631)) and exc == {4625}, f"{sorted(inc)[:3]}… / {exc}")

    from click.testing import CliRunner
    import evtx_tool.cli as C
    import tempfile
    f = os.path.join(tempfile.mkdtemp(prefix="eidrange_"), "placeholder.evtx")
    open(f, "wb").close()                  # the CLI looks for files before it builds the filter
    r = CliRunner().invoke(C.cli, ["parse", "--no-tui", "--event-id", "4630-4624", f])
    check("the CLI refuses --event-id 4630-4624", r.exit_code != 0 and "4630-4624" in (r.output or ""),
          f"exit {r.exit_code}: {(r.output or '').strip()[-160:]}")

    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.filter_dialog import FilterDialog
    dlg = FilterDialog({})
    for chk in dlg._level_checks.values():
        chk.setChecked(False)
    errs = dlg._validate_inputs()
    check("the dialog refuses OK with no Event Type ticked", bool(errs), repr(errs))
    dlg.close()
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
