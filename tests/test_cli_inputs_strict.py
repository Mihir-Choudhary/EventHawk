"""CLI inputs: nothing fails open, the timeline window intersects, log text is not markup.

Gemini audit 11-12 / 11-16 / 11-19 / 11-08 / 11-21 / 11-04 / 11-14:
- 11-12: "-e !4624" was skipped (with nothing left, every event matched);
  "-e" of only invalid specs set no filter; --exclude-id replaced a saved
  filter's exclusions;
- 11-16: --timeline-anchor overwrote --date-from/--date-to and a saved
  filter's dates; negative --timeline-before/after were accepted;
- 11-19: --limit 0 (and negative), --max-threads 0 were accepted;
- 11-08 / 11-21: log values with "[...]" were read as Rich markup in the
  events table, and a missing source file (None) raised;
- 11-04: interactive profile input with an invalid number was ignored
  (no filter at all);
- 11-14: version_info said MIT (the LICENSE is Apache 2.0).

Expected: each handled.  Synthetic.
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def bf(**kw):
    from evtx_tool import cli
    args = dict(event_id=(), level=None, date_from=None, date_to=None, user=(), computer=(), source=(),
                search=(), search_mode="any", exclude_id=(), filter_file=None)
    args.update(kw)
    return cli._build_filter(**args)


def main() -> int:
    import click
    from evtx_tool import cli
    fc = bf(event_id=("!4624",))
    check("-e !4624 is an exclusion", 4624 in (fc.get("exclude_event_ids") or []), str(fc.get("exclude_event_ids")))
    try:
        bf(event_id=("abc",))
        bad = False
    except click.BadParameter:
        bad = True
    check("-e with no valid Event ID is an error, not 'all events'", bad)

    import json
    import tempfile
    ff = os.path.join(tempfile.mkdtemp(prefix="cli_"), "f.json")
    from evtx_tool.core.filters import empty_filter
    saved = empty_filter()
    saved["exclude_event_ids"] = [7036]
    saved["date_from"] = "2026-01-01T10:00:00"
    saved["date_to"] = "2026-01-01T12:00:00"
    open(ff, "w", encoding="utf-8").write(json.dumps(saved))
    fc = bf(exclude_id=("4688",), filter_file=ff)
    check("--exclude-id adds to the saved filter's exclusions", set(fc.get("exclude_event_ids") or []) == {7036, 4688},
          str(fc.get("exclude_event_ids")))
    fc2 = cli._intersect_window(dict(saved), ("2026-01-01T09:00:00", "2026-01-01T11:00:00"), None, None) \
        if hasattr(cli, "_intersect_window") else {}
    check("the timeline window intersects the saved dates",
          (fc2.get("date_from"), fc2.get("date_to")) == ("2026-01-01T10:00:00", "2026-01-01T11:00:00"), str(fc2))

    from click.testing import CliRunner
    r = CliRunner()
    for args, name in ((["parse", ".", "--limit", "0"], "--limit 0"), (["parse", ".", "--max-threads", "0"], "--max-threads 0"),
                       (["parse", ".", "--timeline-before", "-5"], "a negative --timeline-before")):
        res = r.invoke(cli.cli, args)
        check(f"{name} is refused", res.exit_code == 2, f"exit {res.exit_code}")

    from rich.console import Console
    buf = io.StringIO()
    old = cli.console
    cli.console = Console(file=buf, width=200, force_terminal=False)
    try:
        cli._print_events_table([{"timestamp": "2026-01-01T00:00:00Z", "event_id": 1, "level_name": "Information",
                                  "channel": "[bold]Ch[/bold]", "computer": "[red]PC", "source_file": None}])
        out = buf.getvalue()
        ok = "[bold]Ch[/bold]" in out and "[red]PC" in out
    except Exception as exc:
        ok, out = False, f"{type(exc).__name__}: {exc}"
    finally:
        cli.console = old
    check("log text in the events table is shown as written, None source is fine", ok, out[-160:])

    lic = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "version_info.txt"),
               encoding="utf-8").read()
    check("version_info states the Apache 2.0 license", "Apache License 2.0" in lic and "MIT" not in lic)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
