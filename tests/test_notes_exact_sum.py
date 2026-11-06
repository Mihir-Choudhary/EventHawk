"""The downtime Notes equation adds up exactly, and matches the duration shown.

Codex retest 2026-11-06, RT6-2: a real WiFi Notes line read
"95,421s = 13,798s + 53,652s + 27,970s" - the displayed parts total 95,420s,
and the shown connected time (41,769s) was 1s more than before + after
(41,768s).  Each part was cut to whole seconds on its own, then printed as an
equality.  The arithmetic underneath was right; the display was not.

Expected (R30): every duration in the Notes and the "(downtime subtracted)"
cell is exact to the microsecond (the fraction is shown only when there is
one, as logon-session durations already do), so
  * the parts after "Span X =" add up to X exactly;
  * X is exactly the time from connect to disconnect;
  * "N subtracted" is exactly the down/asleep parts;
  * the duration cell equals the connected parts exactly.
Synthetic events (Codex's shape: fractional times, and a sleep plus a restart).
"""
import os
import re
import sys
from datetime import timedelta
from decimal import Decimal

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_wifi_downtime import down_up, at                          # noqa: E402
from test_sleep_downtime import sleep_pt                            # noqa: E402

CHECKS = []
DUR = re.compile(r"^(?:(\d+)h )?(?:(\d+)m )?(\d+(?:\.\d+)?)s")


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def secs(text: str) -> Decimal:
    m = DUR.match(text.strip())
    if not m:
        raise ValueError(f"no duration at the start of {text!r}")
    h, mi, s = m.groups()
    return Decimal(h or 0) * 3600 + Decimal(mi or 0) * 60 + Decimal(s)


def exact(td: timedelta) -> Decimal:
    return Decimal(td.days * 86400 + td.seconds) + Decimal(td.microseconds) / Decimal(10 ** 6)


def grade(tag, res, span, down):
    note = res.get("note", "")
    print(f"  [{tag}] {note}")
    m = re.search(r"Span (.+?) = (.+)\.$", note)
    check(f"{tag}: the Notes hold a Span equation", m is not None)
    if not m:
        return
    parts = [p.strip() for p in m.group(2).split(" + ")]
    shown_span = secs(m.group(1))
    vals = [secs(p) for p in parts]
    check(f"{tag}: the parts add up to the Span exactly", sum(vals) == shown_span,
          f"{sum(vals)} vs {shown_span}")
    check(f"{tag}: the Span is exactly connect -> disconnect", shown_span == exact(span),
          f"{shown_span} vs {exact(span)}")
    sub = secs(note.split(" subtracted:")[0])
    downs = sum(v for v, p in zip(vals, parts) if "(subtracted)" in p)
    check(f"{tag}: 'N subtracted' is exactly the down parts and the real downtime",
          sub == downs == exact(down), f"{sub} / {downs} / {exact(down)}")
    from evtx_tool.analysis.host_power import fmt_secs
    cell = secs(fmt_secs(res["seconds"]))
    conn = sum(v for v, p in zip(vals, parts) if "(subtracted)" not in p)
    check(f"{tag}: the duration cell equals the connected parts exactly", cell == conn,
          f"cell {cell} vs parts {conn}")


def main() -> int:
    from evtx_tool.analysis.host_power import HostPower
    s = T.T0
    # Codex's shape: before 13,798.7 s, asleep 53,652.466385 s, span 95,421.86343 s.
    a, b, e = 13798.7, 13798.7 + 53652.466385, 95421.86343
    p = HostPower([sleep_pt("HOST-F", 10, a, b)])
    res = p.assess("HOST-F", at(0), at(e))
    check("fractional sleep: subtracted", bool(res) and res.get("kind") == "subtracted", repr(res)[:200])
    if res and res.get("kind") == "subtracted":
        grade("fractional sleep", res, timedelta(seconds=e), timedelta(seconds=b) - timedelta(seconds=a))

    # A sleep and a restart in one session, fractional everywhere.
    evs = [sleep_pt("HOST-G", 10, 500.25, 700.5)] + down_up("HOST-G", 20, 1000.9, 1600.35)
    p = HostPower(evs)
    res = p.assess("HOST-G", at(0.6), at(2000.123456))
    check("sleep + restart: subtracted", bool(res) and res.get("kind") == "subtracted", repr(res)[:200])
    if res and res.get("kind") == "subtracted":
        down = (timedelta(seconds=700.5) - timedelta(seconds=500.25)) + \
               (timedelta(seconds=1600.35) - timedelta(seconds=1000.9))
        grade("sleep + restart", res, timedelta(seconds=2000.123456) - timedelta(seconds=0.6), down)

    # Whole seconds still read as before (no ".0").
    from evtx_tool.analysis.host_power import fmt_secs
    check("whole seconds keep their old form", (fmt_secs(3725), fmt_secs(65), fmt_secs(5)) ==
          ("1h 02m 05s", "1m 05s", "5s"), repr((fmt_secs(3725), fmt_secs(65), fmt_secs(5))))
    check("a fraction is shown exactly, trailing zeros dropped",
          (fmt_secs(3725.5), fmt_secs(0.000001), fmt_secs(61.250000)) == ("1h 02m 05.5s", "0.000001s", "1m 01.25s"),
          repr((fmt_secs(3725.5), fmt_secs(0.000001), fmt_secs(61.25))))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
