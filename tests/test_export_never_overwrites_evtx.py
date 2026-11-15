"""An export never overwrites an EVTX log, and a failed export leaves no half-written file.

Gemini audit 6-11 (Critical): exporters.export() turned an unknown extension
into JSON, so `parse case.evtx -o case.evtx` (or `diff ... -o inc.evtx`)
truncated the evidence file and wrote JSON over it.  A writer that failed half
way left a truncated file at the destination.

Expected (exporters.export, used by the CLI and by the GUI's export paths):
- an output path ending in .evtx is refused, in every format, and the file is
  untouched;
- an existing file that IS an EVTX log ("ElfFile\\0" header) is refused whatever
  its name;
- an export that raises half way leaves the destination as it was (absent, or
  its old content) and no temporary file behind;
- a normal export still writes the file; another unknown extension still gives
  JSON (unchanged).
Synthetic data only.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
MAGIC = b"ElfFile\x00" + b"\x00" * 120


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(i):
    return {"record_id": i, "event_id": 4624, "timestamp": "2026-01-01T00:00:00.000000Z", "channel": "Security",
            "provider": "P", "computer": "HOST-A", "level": 0, "level_name": "Information",
            "event_data": {"X": str(i)}, "source_file": "a.evtx"}


class Boom(list):
    """A list of events whose iteration fails after the first event."""
    def __iter__(self):
        yield ev(1)
        raise RuntimeError("disk gone")


def main() -> int:
    from evtx_tool.output import exporters
    d = tempfile.mkdtemp(prefix="eh_exp_")

    def raises(fn):
        try:
            fn()
            return None
        except Exception as e:     # noqa: BLE001
            return e

    # 1. .evtx destination, existing log
    p = os.path.join(d, "case.evtx")
    open(p, "wb").write(MAGIC)
    for fmt in (None, "json", "csv", "xml", "html"):
        e = raises(lambda: exporters.export([ev(1)], p, fmt))
        check(f"export to an existing .evtx (fmt={fmt}) is refused and the log is untouched",
              e is not None and open(p, "rb").read() == MAGIC, repr(e))
    # 2. .evtx destination that does not exist yet
    p2 = os.path.join(d, "new.evtx")
    e = raises(lambda: exporters.export([ev(1)], p2))
    check("export to a new .evtx path is refused and nothing is created", e is not None and not os.path.exists(p2),
          repr(e))
    # 3. an EVTX log under another name
    p3 = os.path.join(d, "renamed_log.json")
    open(p3, "wb").write(MAGIC)
    e = raises(lambda: exporters.export([ev(1)], p3, "json"))
    check("an existing EVTX log named .json is refused and untouched",
          e is not None and open(p3, "rb").read() == MAGIC, repr(e))

    # 4. failure half way
    for fmt in ("json", "csv", "xml", "html"):
        new = os.path.join(d, f"fail_new.{fmt}")
        e = raises(lambda: exporters.export(Boom(), new, fmt))
        check(f"{fmt}: a failed export to a new path leaves no file", e is not None and not os.path.exists(new),
              repr(e))
        old = os.path.join(d, f"fail_old.{fmt}")
        open(old, "w", encoding="utf-8").write("previous report")
        e = raises(lambda: exporters.export(Boom(), old, fmt))
        check(f"{fmt}: a failed export over an old report keeps the old report",
              e is not None and open(old, encoding="utf-8").read() == "previous report", repr(e))
    left = [n for n in os.listdir(d) if n not in ("case.evtx", "renamed_log.json") and not n.startswith("fail_old")]
    check("no temporary file is left behind", not left, str(left))

    # 5. normal exports still work
    ok = os.path.join(d, "ok.json")
    n = exporters.export([ev(1), ev(2)], ok)
    check("a normal JSON export writes both events", n == 2 and len(json.load(open(ok, encoding="utf-8"))) == 2)
    txt = os.path.join(d, "ok.txt")
    exporters.export([ev(1)], txt)
    check("another unknown extension still gives JSON (unchanged)",
          isinstance(json.load(open(txt, encoding="utf-8")), list))
    csvp = os.path.join(d, "ok.csv")
    exporters.export([ev(1)], csvp)
    check("a CSV export over nothing writes a file", os.path.getsize(csvp) > 0)

    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
