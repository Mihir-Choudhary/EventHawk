"""Every evidence-loss finding must reach the examiner, not just a log file.

The parse engines detect several kinds of record loss. Each one is only useful
if the analyst SEES it -- a warning that reaches nothing but a rotating log is
indistinguishable from a clean parse, and a clean-looking parse is exactly how
missing evidence goes unnoticed.

The bug this suite exists for: normal mode filtered warnings with a substring
WHITELIST --

    "could not be parsed" in w or "ABORTED" in w or "TRUNCATED" in w

-- while the engine writes "parse aborted mid-file" (lowercase) and
"record(s) ... were not parsed". Two of the most severe findings, including the
one meaning every record after the failure point is gone, silently never
appeared. A whitelist fails closed on anything it does not recognise; the
classification now lives at the call site, and the GUI shows everything not
explicitly tagged benign.

Run: QT_QPA_PLATFORM=offscreen python tests/test_no_silent_errors.py
"""
import os, re, sys, ast

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ENGINE = os.path.join(ROOT, "evtx_tool", "core", "engine.py")
MAINWIN = os.path.join(ROOT, "evtx_tool", "gui", "main_window.py")

# Messages that are NOT evidence loss. Anything else must be shown.
BENIGN_HINTS = ("Ctrl+C", "RAM pressure", "throttled to")


def main() -> int:
    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    # ── 1. every append_warning call site is classified ──────────────────
    src = open(ENGINE, encoding="utf-8").read()
    tree = ast.parse(src)
    sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and fn.attr == "append_warning"):
            continue
        benign = any(kw.arg == "benign" and getattr(kw.value, "value", False) is True
                     for kw in node.keywords)
        try:
            text = ast.get_source_segment(src, node.args[0]) if node.args else ""
        except Exception:
            text = ""
        sites.append((node.lineno, benign, (text or "").strip()))

    check("append_warning call sites were found", len(sites) >= 5,
          f"{len(sites)} site(s)")

    mismatched = []
    for lineno, benign, text in sites:
        looks_benign = any(h in text for h in BENIGN_HINTS)
        if benign != looks_benign:
            mismatched.append(
                f"engine.py:{lineno} benign={benign} but text={text[:60]!r}")
    check("every warning is classified consistently with its text",
          not mismatched, "\n      ".join(mismatched))

    n_benign = sum(1 for _, b, _ in sites if b)
    check("the loss-bearing warnings are NOT tagged benign",
          n_benign == len([1 for _, _, t in sites
                           if any(h in t for h in BENIGN_HINTS)]),
          f"{n_benign} tagged benign of {len(sites)}")

    # ── 2. the GUI must not use a substring whitelist ────────────────────
    gui = open(MAINWIN, encoding="utf-8").read()
    check("normal mode no longer whitelists warnings by substring",
          '"ABORTED" in w' not in gui and '"could not be parsed" in w' not in gui,
          "a substring whitelist hides any warning it does not recognise")
    check("normal mode filters by the engine's benign tag instead",
          "parse_benign_warnings" in gui)

    # ── 3. live behaviour: real strings through the real classifier ──────
    from evtx_tool.core.engine import EngineState
    st = EngineState()
    real = [
        ("truncation",      "S.evtx: file appears TRUNCATED — header declares 400 chunk(s) "
                            "but the file only contains 320 (acquisition may be incomplete)", False),
        ("abort mid-file",  "S.evtx: parse aborted mid-file (chunk 12 checksum mismatch)", False),
        ("missing records", "S.evtx: 1,204 record(s) declared in chunk headers were not parsed "
                            "— see Missing Record IDs for the exact gaps", False),
        ("skipped records", "S.evtx: 37 record(s) could not be parsed and were skipped", False),
        ("ctrl-c",          "Ctrl+C detected — stopping...", True),
        ("ram pressure",    "RAM pressure persists — continuing with reduced throughput", True),
        ("cpu throttle",    "CPU > 85% — throttled to 4 workers", True),
    ]
    for _n, msg, benign in real:
        st.append_warning(msg, benign=benign)

    benign_set = set(st.benign_warnings)
    shown = [w for w in st.warnings if w not in benign_set]

    loss = [m for _n, m, b in real if not b]
    perf = [m for _n, m, b in real if b]
    check("all four evidence-loss warnings are shown",
          all(m in shown for m in loss),
          f"{sum(1 for m in loss if m in shown)}/{len(loss)} shown")
    check("the abort warning specifically is shown (the silent one)",
          any("parse aborted mid-file" in w for w in shown))
    check("the 'were not parsed' warning is shown (the other silent one)",
          any("were not parsed" in w for w in shown))
    check("performance notices stay quiet (no alert fatigue)",
          not any(m in shown for m in perf),
          f"{sum(1 for m in perf if m in shown)} performance notice(s) leaked in")

    # ── 4. an UNRECOGNISED warning must fail loud ────────────────────────
    st2 = EngineState()
    st2.append_warning("Brand new failure mode nobody has seen before")
    check("an unknown warning defaults to SHOWN, not hidden",
          "Brand new failure mode nobody has seen before" not in set(st2.benign_warnings))

    # ── 4b. END TO END: the warning must reach the real dialog ───────────
    #     Sections 1-4 prove the classifier. They would still pass if the
    #     dialog never consulted it, so drive the actual handler and read the
    #     text the analyst would see.
    import time as _time
    from PySide6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow

    ABORT = "Security.evtx: parse aborted mid-file (chunk 12 checksum mismatch)"
    NOTPARSED = ("Security.evtx: 1,204 record(s) declared in chunk headers were "
                 "not parsed — see Missing Record IDs for the exact gaps")
    THROTTLE = "CPU > 85% — throttled to 4 workers"

    class _StubWorker:
        parse_warnings = [ABORT, NOTPARSED, THROTTLE]
        parse_benign_warnings = [THROTTLE]
        parse_errors: list = []

    shown_text = []
    _orig_warn = QMessageBox.warning
    QMessageBox.warning = staticmethod(
        lambda parent, title, text, *a, **k: (shown_text.append((title, text)), 0)[1])
    win = None
    try:
        win = MainWindow()
        win._worker = _StubWorker()
        win._parse_start_ts = _time.monotonic()
        win._on_parse_finished([], None, False, False)
    except Exception as exc:
        shown_text.append(("__handler_raised__", f"{type(exc).__name__}: {exc}"))
    finally:
        QMessageBox.warning = _orig_warn
        if win is not None:
            win.close()
        app.processEvents()

    raised = [t for t, _ in shown_text if t == "__handler_raised__"]
    check("the real parse-finished handler runs", not raised,
          next((x for t, x in shown_text if t == "__handler_raised__"), ""))

    integrity = "\n".join(txt for title, txt in shown_text
                          if "Integrity" in str(title))
    check("END TO END: 'parse aborted mid-file' reaches the dialog",
          "parse aborted mid-file" in integrity,
          f"dialog text was: {integrity[:160]!r}")
    check("END TO END: 'were not parsed' reaches the dialog",
          "were not parsed" in integrity,
          f"dialog text was: {integrity[:160]!r}")
    check("END TO END: the throttle notice stays out of the dialog",
          "throttled to" not in integrity,
          "a performance notice in a loss dialog trains the analyst to dismiss it")

    # ── 5. elided counts and the watchdog ────────────────────────────────
    check("elided problem lines state how many were omitted",
          gui.count("and {len(_lines) - 15:,} more") >= 1
          and gui.count("and {len(_problems) - 15:,} more") >= 1,
          'a bare "…" hides how much was left out')
    check("a failing integrity check itself warns the analyst",
          gui.count("Parse Integrity Check Failed") == 2,
          f"{gui.count('Parse Integrity Check Failed')} of 2 handlers surface it")

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
