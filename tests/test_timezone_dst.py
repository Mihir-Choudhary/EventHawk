"""Filtering and display must agree on what day an event happened.

Timestamps are stored in UTC and rendered in the analyst's display timezone.
Three places converted between the two by reading the CURRENT local UTC offset
(`datetime.now().astimezone().utcoffset()`) and stamping it onto a log
timestamp. An offset is only true for the instant it was read, so in any
DST-observing zone a log from the other season is converted with the wrong
rule:

    analyst working in July (EDT, -4), filtering January logs (EST, -5)
      filter boundary 2025-01-15 00:00 local -> 04:00Z   (today's offset)
      table displays  2025-01-15 05:00Z      -> 00:00    (that date's rule)

One hour apart, silently. "Show me 15 January" then returns 23:00 on the 14th
through 22:59 on the 15th — events attributed to the wrong day of a timeline,
with nothing on screen to say so.

A naive datetime handed to `.astimezone()` is interpreted as system local time
and resolved with the rules in force ON ITS OWN DATE, which is what the display
path (`apply_tz`) already did. For the DuckDB date-grouping expression the
equivalent is `AT TIME ZONE '<IANA name>'` rather than an INTERVAL of seconds.

Run: TZ=America/New_York QT_QPA_PLATFORM=offscreen python tests/test_timezone_dst.py
"""
import os, sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("TZ", "America/New_York")     # a zone that observes DST
import time as _time
try:
    _time.tzset()
except AttributeError:
    pass
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.models import _tz_state, apply_tz
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    from evtx_tool.gui.jm_col_worker import _timestamp_date_expr, _system_tz_name

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    # Winter and summer instants that BOTH render as local midnight.
    CASES = [("winter (EST, -5)", "2025-01-15 00:00:00", "2025-01-15T05:00:00.000000Z"),
             ("summer (EDT, -4)", "2025-07-15 00:00:00", "2025-07-15T04:00:00.000000Z")]

    check("the test timezone actually observes DST (test is meaningful)",
          apply_tz("2025-01-15T05:00:00.000000Z")[:19]
          != apply_tz("2025-07-15T05:00:00.000000Z")[:19],
          "same UTC clock time must render differently in the two seasons")

    prev_mode = _tz_state.get("mode")
    try:
        _tz_state["mode"] = "local"

        # ── display side ────────────────────────────────────────────────
        for label, want_local, utc in CASES:
            got = apply_tz(utc)[:19]
            check(f"display renders {label} correctly", got == want_local,
                  f"{utc[:19]}Z -> {got}, want {want_local}")

        # ── filter side must agree with it ──────────────────────────────
        for label, boundary, utc in CASES:
            _sql, params = filter_config_to_sql(
                {"date_from": boundary, "date_to": boundary, "date_mode": "range"})
            conv = [p for p in params if isinstance(p, str) and p.startswith("2025")]
            want = utc[:19].replace("T", " ")
            check(f"filter converts the {label} boundary to the same instant",
                  bool(conv) and conv[0] == want,
                  f"filter -> {conv[:1]}, display shows that local time as {want}Z")

        # ── the DuckDB date-grouping expression ─────────────────────────
        expr = _timestamp_date_expr()
        check("local-mode date grouping resolves DST per event, not by a fixed offset",
              "AT TIME ZONE" in expr,
              f"expr={expr[:90]!r} — an INTERVAL of seconds cannot express DST")
        check("the system timezone name is resolvable",
              bool(_system_tz_name()), str(_system_tz_name()))

        if "AT TIME ZONE" in expr:
            import duckdb
            con = duckdb.connect()
            try:
                con.execute("INSTALL icu; LOAD icu;")
            except Exception:
                pass
            ok_rows = []
            for label, want_local, utc in CASES:
                v = utc[:19].replace("T", " ")
                q = f"SELECT {expr.replace('timestamp_utc', repr(v))}"
                try:
                    ok_rows.append((label, con.execute(q).fetchone()[0], want_local[:10]))
                except Exception as exc:
                    ok_rows.append((label, f"ERROR {exc}", want_local[:10]))
            con.close()
            bad = [r for r in ok_rows if r[1] != r[2]]
            check("grouped date matches the displayed date in BOTH seasons",
                  not bad, "; ".join(f"{l}: got {g} want {w}" for l, g, w in ok_rows))
    finally:
        if prev_mode is not None:
            _tz_state["mode"] = prev_mode

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
