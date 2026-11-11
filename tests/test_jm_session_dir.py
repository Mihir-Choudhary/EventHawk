"""Each Juggernaut parse gets its own data folder (audit SA-1).

Every Juggernaut parse used the one folder %TEMP%\\evtx_jm_session and deleted
it first.  A second EventHawk window parsing in Juggernaut mode therefore
deleted the first window's shards and wrote its own under the same names:
reproduced with two real logs, window A's shard paths went from 290 events of
log A to 65 events of log B.  Expected: every parse writes to a folder of its
own; another parse never touches it; a stopped or failed parse leaves no
folder behind; a folder left by an EventHawk that is no longer running is
removed, one whose EventHawk still runs is kept.  The engine is replaced by a
stand-in that writes one marker file, so no logs are needed.
"""
import os
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


class FakeEngine:
    fail = False
    seen = []

    def __init__(self, parquet_dir, on_progress=None):
        self.d = parquet_dir
        FakeEngine.seen.append(parquet_dir)

    def run(self, files, filter_config):
        with open(os.path.join(self.d, "shard_00000.parquet"), "w") as f:
            f.write(files[0])
        with open(os.path.join(self.d, "parquet_manifest.json"), "w") as f:
            f.write("[]")
        if FakeEngine.fail:
            raise RuntimeError("engine failed")
        return self.d

    def stop(self):
        pass


def parse(name, stop=False):
    from evtx_tool.gui.heavyweight_worker import HeavyweightParseWorker
    out = {}
    w = HeavyweightParseWorker([name], None)
    w.finished.connect(lambda d: out.__setitem__("dir", d))
    w.error.connect(lambda e: out.__setitem__("err", e))
    w.cancelled.connect(lambda: out.__setitem__("cancelled", True))
    if stop:
        w.request_stop()
    w.run()
    return out


def marker(d):
    try:
        with open(os.path.join(d, "shard_00000.parquet")) as f:
            return f.read()
    except OSError:
        return None


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])   # noqa: F841
    import evtx_tool.core.heavyweight.engine as eng
    real = eng.HeavyweightEngine
    eng.HeavyweightEngine = FakeEngine
    made = []
    try:
        a = parse("log A")
        b = parse("log B")
        made += [a.get("dir"), b.get("dir")]
        check("two parses use two different folders", a.get("dir") and b.get("dir") and a["dir"] != b["dir"],
              f"{os.path.basename(a.get('dir') or '')} / {os.path.basename(b.get('dir') or '')}")
        check("the first parse's data is untouched by the second", marker(a.get("dir") or "") == "log A",
              f"first folder holds {marker(a.get('dir') or '')!r}")
        check("the second parse holds its own data", marker(b.get("dir") or "") == "log B")

        FakeEngine.seen.clear()
        FakeEngine.fail = True
        e = parse("log C")
        FakeEngine.fail = False
        check("a failed parse reports its error", "engine failed" in (e.get("err") or ""))
        check("a failed parse leaves no folder", FakeEngine.seen and not os.path.exists(FakeEngine.seen[-1]))

        FakeEngine.seen.clear()
        c = parse("log D", stop=True)
        check("a stopped parse says so", c.get("cancelled") is True)
        check("a stopped parse leaves no folder", FakeEngine.seen and not os.path.exists(FakeEngine.seen[-1]))

        # A folder left by an EventHawk that no longer runs / that still runs.
        p = subprocess.Popen([sys.executable, "-c", "pass"])
        p.wait()
        dead = os.path.join(tempfile.gettempdir(), f"evtx_jm_session_{p.pid}_leftover")
        live = os.path.join(tempfile.gettempdir(), f"evtx_jm_session_{os.getppid()}_other")
        for d in (dead, live):
            os.makedirs(d, exist_ok=True)
        made += [dead, live]
        d = parse("log E")
        made.append(d.get("dir"))
        check("a folder left by an EventHawk that is gone is removed", not os.path.exists(dead))
        check("a folder of an EventHawk that still runs is kept", os.path.isdir(live))
        check("this window's earlier folders are kept", marker(a.get("dir") or "") == "log A"
              and marker(b.get("dir") or "") == "log B")
    finally:
        eng.HeavyweightEngine = real
        for d in made:
            if d:
                shutil.rmtree(d, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
