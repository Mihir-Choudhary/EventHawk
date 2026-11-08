"""A file that cannot be opened says WHY and what to do -- and nothing is lost.

A log Windows would not let the user read showed "Parse error X.evtx: Access
is denied. (os error 5)" in Normal mode and only "file could not be opened" in
Juggernaut -- no cause, no next step -- and Juggernaut appended the "A parse
ABORT means ..." note although nothing aborted.

The explanation is ADDED to the existing pipeline.  Everything already there
must survive unchanged, so most checks here are about what is kept:

  * explain_open_errors() recognises access denied / in use / not found from
    the OS text, counts files per cause, and says nothing for other problems;
  * through the real MainWindow, with a real permission-locked copy of a log
    (Windows file ACL), in Normal and Juggernaut mode:
      - the exact OS error text stays on the file's line;
      - the explanation is shown below it;
      - Normal's "nothing loaded" error still names the log folder
        (logsetup.log_directory()) and Help > Open Log Folder;
      - Juggernaut still points at parse_stats.json, keeps the ABORT note when
        another file really aborted, and drops it when none did;
      - a readable file next to the locked one still loads; a clean parse
        shows no warning.

Run: QT_QPA_PLATFORM=offscreen python tests/test_open_error_messages.py
     (set EVTX_TEST_LOGS for the end-to-end part; it is Windows-only)
"""
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def main() -> int:
    from evtx_tool.core.open_errors import explain_open_errors, open_error_causes

    print("=== 1. cause matching ===")
    samples = {
        "Parse error A.evtx: Access is denied. (os error 5)": ["access"],
        "B.evtx: [Errno 13] Permission denied: 'B.evtx'": ["access"],
        "Parse error C.evtx: The process cannot access the file because it is "
        "being used by another process. (os error 32)": ["in_use"],
        "D.evtx: The system cannot find the file specified. (os error 2)": ["missing"],
        "E.evtx: The system cannot find the path specified. (os error 3)": ["missing"],
        "F.evtx: parse aborted mid-file (invalid chunk header)": [],
        "Timeout (300s): G.evtx": [],
    }
    for text, want in samples.items():
        check(f"{text[:44]!r}… -> {want or 'none'}", open_error_causes(text) == want)
    why = explain_open_errors(list(samples))
    check("one paragraph per cause, with its file count",
          why.count("2 file(s) — “Access is denied”") == 1
          and why.count("1 file(s) — “In use”") == 1
          and why.count("2 file(s) — “Not found”") == 1, why[:120])
    check("nothing to explain -> empty", explain_open_errors(["F.evtx: parse aborted"]) == "")

    LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")

    def has_events(p):
        try:
            import evtx
            return next(iter(evtx.PyEvtxParser(p).records()), None) is not None
        except Exception:
            return False
    real = [p for p in sorted(glob.glob(os.path.join(LOGS, "*.evtx")), key=os.path.getsize)
            if os.path.getsize(p) > 200_000 and has_events(p)]
    multi = [p for p in real if os.path.getsize(p) >= 4096 + 8 * 65536]
    if os.name != "nt" or len(real) < 2 or not multi:
        print("\n  (not Windows, or no corpus with a multi-chunk log — end-to-end part skipped)")
        return finish()

    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui import main_window as mw
    from evtx_tool.core.logsetup import log_directory

    tmp = tempfile.mkdtemp(prefix="eh_open_err_")
    locked = os.path.join(tmp, "Locked.evtx")
    readable = os.path.join(tmp, "Readable.evtx")
    aborts = os.path.join(tmp, "Aborts.evtx")
    shutil.copyfile(real[0], locked)
    shutil.copyfile(real[1], readable)
    shutil.copyfile(min(multi, key=os.path.getsize), aborts)
    # one record's signature broken in chunk 2 -> the primary parse aborts there
    d = bytearray(open(aborts, "rb").read())
    base = 4096 + 2 * 65536
    sig = [m.start() for m in re.finditer(rb"\x2a\x2a\x00\x00", bytes(d[base + 0x200:base + 65536]))][4]
    d[base + 0x200 + sig: base + 0x200 + sig + 4] = b"XXXX"
    open(aborts, "wb").write(d)
    subprocess.run(["icacls", locked, "/inheritance:r", "/grant:r", "*S-1-5-18:F"],
                   capture_output=True, check=True)
    seen = []
    orig_warn = mw.MainWindow._warn_blocking
    mw.MainWindow._warn_blocking = lambda self, title, text, **k: seen.append((title, text))
    try:
        try:
            open(locked, "rb").close()
            check("the copy is really locked", False, "still readable")
            return finish()
        except PermissionError:
            check("the copy is really locked", True)

        def pump(sec, until=None):
            end = time.time() + sec
            while time.time() < end:
                app.processEvents(); time.sleep(0.02)
                if until and until():
                    return True
            return False

        def run(mode, files):
            seen.clear()
            w = mw.MainWindow()
            if mode == "normal":
                for f in files:
                    w._add_path(f)
                w._on_parse_clicked()
                pump(240, lambda: bool(seen) or (w._active_proxy is not None
                                                 and w._active_proxy.rowCount() > 0
                                                 and w._btn_parse.isEnabled()))
                pump(2)
                rows = w._active_proxy.rowCount() if w._active_proxy is not None else 0
            else:
                w._launch_juggernaut_mode(files)
                pump(300, lambda: bool(seen) or (w._hw_model is not None
                                                 and w._hw_model.rowCount() > 0))
                pump(3)
                rows = w._hw_model.rowCount() if w._hw_model is not None else 0
            w.close(); pump(0.5)
            return rows, "\n".join(t for _, t in seen)

        EXPL = "“Access is denied”: Windows blocked reading the file"
        OS_TEXT = "Access is denied. (os error 5)"

        print("\n=== 2. Normal mode ===")
        rows, text = run("normal", [locked, readable])
        check("readable file still loads beside the locked one", rows > 0, f"{rows:,}")
        check("the OS error text is kept on the file's line",
              f"Parse error Locked.evtx: {OS_TEXT}" in text)
        check("the explanation is shown", EXPL in text)
        rows, text = run("normal", [locked])
        check("locked only: nothing loads, and the error says why", rows == 0 and EXPL in text)
        check("…and still names the log folder and Help > Open Log Folder",
              f"Details are in eventhawk_gui.log, in {log_directory()}" in text
              and "Help > Open Log Folder" in text, text[-160:])
        rows, text = run("normal", [readable])
        check("a clean parse shows no warning", rows > 0 and not text, text[:100])

        print("\n=== 3. Juggernaut mode ===")
        rows, text = run("jm", [locked, readable])
        check("readable file still loads beside the locked one", rows > 0, f"{rows:,}")
        check("the file's line keeps the OS reason",
              f"file could not be opened ({OS_TEXT})" in text, text[:200])
        check("the explanation is shown", EXPL in text)
        check("no ABORT note when nothing aborted", "parse ABORT" not in text)
        check("still points at parse_stats.json", "parse_stats.json in the session directory" in text)
        rows, text = run("jm", [locked, aborts])
        check("a real abort in another file is still reported",
              "Aborts.evtx: parse aborted mid-file" in text, text[:240])
        check("…and its ABORT note is kept, beside the explanation",
              "A parse ABORT means" in text and EXPL in text)
        rows, text = run("jm", [readable])
        check("a clean parse shows no warning", rows > 0 and not text, text[:100])
    finally:
        mw.MainWindow._warn_blocking = orig_warn
        subprocess.run(["icacls", locked, "/reset"], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
    return finish()


def finish() -> int:
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
