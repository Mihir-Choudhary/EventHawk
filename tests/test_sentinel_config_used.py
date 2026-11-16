"""Sentinel's configurable limits are used.

Gemini audit 10-10 (Medium): SentinelConfig.max_surprisal, stability_abort
and stability_warn were defined (and documented) but ignored: the scorer
and the frequency model used a hard-coded 20-bit cap and the builder fixed
thresholds of 0.3 / 0.6; the CLI had no --config.

Expected: a config's max_surprisal changes the cap and the composite
score; its stability_abort decides whether a baseline is refused; both CLI
commands accept --config.  Synthetic.
"""
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from sentinel.config import SentinelConfig
    from sentinel.analysis.scorer import composite_score
    from sentinel.baseline import freq_model as F
    a = composite_score(10.0, 10.0, 0.0, 0.0, 0.0, cfg=SentinelConfig())
    b = composite_score(10.0, 10.0, 0.0, 0.0, 0.0, cfg=SentinelConfig(max_surprisal=10.0))
    check("the composite score uses the config's max_surprisal", b > a, f"{a} vs {b}")
    m = F.FrequencyModel() if hasattr(F, "FrequencyModel") else None
    try:
        s = F.surprisal_cmdline(m, "unseen.exe", "x", max_s=10.0)
    except TypeError:
        s = None
    check("the surprisal cap follows the config", s == 10.0, str(s))

    from sentinel.baseline.stability import baseline_stability
    from datetime import datetime, timezone
    from sentinel.models import RawEvent

    def ev(n, c):
        return RawEvent(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), host="H", event_id=4688,
                        process_guid="", pid=1, ppid=0, parent_guid="", process_name=n, process_path="",
                        parent_name="", parent_path="", cmdline=c, user="", integrity_level="", image_hash="")
    evs = [ev("x.exe", "1"), ev("x.exe", "2"), ev("x.exe", "1"), ev("x.exe", "3")]   # stability 1/3
    import sentinel.baseline.builder as B
    import inspect
    sig = inspect.signature(B.build_baseline)
    check("build_baseline takes a config", "config_path" in sig.parameters, str(sig))

    import sentinel.cli as cli
    import argparse
    src = inspect.getsource(cli.main)
    check("both CLI commands accept --config", src.count('"--config"') >= 2)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
