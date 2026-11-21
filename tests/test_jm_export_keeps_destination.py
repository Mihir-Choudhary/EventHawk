"""An export never destroys the file the analyst chose: not an event log, not an earlier report.

Codex audit A2-01 (Critical): the Juggernaut export's CSV / JSON path wrote
the chosen file directly, without the event-log check export() has (Gemini
6-11), so an EVTX log renamed .csv or .json was overwritten.  HTML / XML did
refuse it, but on that error (and on any other failure, even one before a
file was opened, such as a missing shard list) the worker deleted the chosen
path: the event log, or an earlier complete report.  The session, IOC,
bookmark, System Activity and Sentinel report exports also wrote the chosen
file directly.

Expected:
  - all four Juggernaut formats refuse an existing EVTX log, whatever its
    name, and leave its bytes as they were;
  - a failed or cancelled Juggernaut export leaves an earlier report as it
    was; a successful one replaces it; no temporary file is left behind;
  - exporters.export_open (the other GUI exports) and the IOC formats refuse
    an event log and keep the earlier file when the write fails;
  - Sentinel's JSON / CSV report refuses an event log.
Synthetic data only.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication                          # noqa: E402

app = QApplication.instance() or QApplication([])
CHECKS = []
FMTS = ("csv", "json", "xml", "html")
EVTX = b"ElfFile\x00" + bytes(range(256)) * 16          # an EVTX header and some bytes
PREVIOUS = b"previous complete report\n"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def run_export(table, shards, path, ext, cancel=False):
    import evtx_tool.gui.main_window as mw
    w = mw._JMExportWorker(table, shards, "1=1", [], "timestamp_utc ASC, source_file ASC, record_id ASC",
                           path, ext, 10 ** 9)
    errs, oks = [], []
    w.failed.connect(errs.append)
    w.finished_ok.connect(lambda n, p: oks.append(n))
    if cancel:
        w.cancel()
    w.run()
    return errs, oks


def content(p):
    return Path(p).read_bytes() if os.path.exists(p) else None


def leftovers(d):
    return [n for n in os.listdir(d) if n.startswith((".eventhawk_export_", ".sentinel_report_"))]


def main() -> int:
    import test_around_pivot as T
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    tmp = tempfile.mkdtemp(prefix="jm_keep_")
    try:
        evs = T.dataset()
        table = T.write_jm(evs, tmp)
        model = ArrowTableModel(table, parquet_dir=tmp)
        shards = list(model._get_shard_paths())
        model.close()
        out_dir = os.path.join(tmp, "out")
        os.makedirs(out_dir)
        print(f"{len(evs)} events, {len(shards)} shard(s)")

        for ext in FMTS:
            p = os.path.join(out_dir, f"renamed_log.{ext}")
            Path(p).write_bytes(EVTX)
            errs, oks = run_export(table, shards, p, ext)
            check(f"{ext}: an EVTX log named .{ext} is refused and left byte for byte",
                  errs and not oks and os.path.exists(p) and content(p) == EVTX,
                  f"failed={errs[:1]} ok={oks} exists={os.path.exists(p)}")

            p = os.path.join(out_dir, f"previous.{ext}")
            Path(p).write_bytes(PREVIOUS)
            errs, oks = run_export(table, [], p, ext)
            check(f"{ext}: a failed export (no shard list) keeps the earlier report",
                  errs and not oks and content(p) == PREVIOUS, f"failed={errs[:1]}")

            errs, oks = run_export(table, shards, p, ext, cancel=True)
            check(f"{ext}: a cancelled export keeps the earlier report",
                  errs == ["__cancelled__"] and content(p) == PREVIOUS, f"failed={errs[:1]} ok={oks}")

            errs, oks = run_export(table, shards, p, ext)
            check(f"{ext}: a successful export replaces the earlier report",
                  not errs and oks and content(p) not in (None, b"", PREVIOUS),
                  f"failed={errs[:1]}")
        check("no temporary export file left behind", not leftovers(out_dir), str(leftovers(out_dir)))

        # The other GUI exports (sessions, IOCs, bookmarks, System Activity).
        from evtx_tool.output.exporters import export_open
        p = os.path.join(out_dir, "sessions.csv")
        Path(p).write_bytes(EVTX)
        try:
            with export_open(p, newline="", encoding="utf-8-sig") as fh:
                fh.write("a,b\n")
            refused = False
        except ValueError:
            refused = True
        check("export_open refuses an EVTX log named .csv and leaves it", refused and content(p) == EVTX)
        p = os.path.join(out_dir, "sessions2.csv")
        Path(p).write_bytes(PREVIOUS)
        try:
            with export_open(p, encoding="utf-8") as fh:
                fh.write("half a report")
                raise RuntimeError("zz simulated failure")
        except RuntimeError:
            pass
        check("export_open keeps the earlier file when the write fails", content(p) == PREVIOUS)
        with export_open(p, encoding="utf-8") as fh:
            fh.write("new report")
        check("export_open replaces the file when the write completes",
              (content(p) or b"").decode("utf-8") == "new report")

        from evtx_tool.output import ioc_formats
        p = os.path.join(out_dir, "iocs.json")
        Path(p).write_bytes(EVTX)
        try:
            ioc_formats.export_stix({"ipv4": []}, p)
            refused = False
        except ValueError:
            refused = True
        check("IOC STIX export refuses an EVTX log named .json", refused and content(p) == EVTX)

        # Sentinel's report.
        from sentinel.report import generator as G
        for name in ("report.json", "report.csv"):
            p = Path(out_dir) / name
            p.write_bytes(EVTX)
            try:
                with G._report_open(p, encoding="utf-8") as fh:
                    fh.write("{}")
                refused = False
            except ValueError:
                refused = True
            check(f"Sentinel {name}: an EVTX log is refused and left", refused and content(p) == EVTX)
        check("no temporary file left behind (all exports)", not leftovers(out_dir), str(leftovers(out_dir)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
