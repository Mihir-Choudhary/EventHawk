"""CLI time bounds and excluded ID ranges are read exactly, or refused (Codex DOC-2, DOC-3).

DOC-2: an offset (+02:00) was stripped, not converted, so the bound selected the
wrong UTC interval; a fractional second was dropped, so the filter (which
compares whole seconds) accepted events on both sides of it; the timeline
anchor rejected offsets.  Expected: offsets converted to UTC; a fraction in
--date-from / --date-to refused with a clear error (never silently changed).
DOC-3: --exclude-id kept only plain numbers, so 4600-4650 excluded nothing.
Expected: ranges work as in --event-id.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def build(**kw):
    from evtx_tool import cli
    args = dict(event_id=(), level=(), date_from=None, date_to=None, user=(), computer=(), source=(),
                search=(), search_mode="AND", exclude_id=(), filter_file=None)
    args.update(kw)
    return cli._build_filter(**args)


def main() -> int:
    import click
    from evtx_tool import cli
    fc = build(date_from="2025-05-10T14:30:00+02:00", date_to="2025-05-10T15:00:00Z")
    check("an offset is converted to UTC", fc.get("date_from") == "2025-05-10T12:30:00"
          and fc.get("date_to") == "2025-05-10T15:00:00", f"{fc.get('date_from')} / {fc.get('date_to')}")
    try:
        build(date_from="2025-05-10T14:30:00.500")
        refused = False
    except click.BadParameter:
        refused = True
    check("a fractional --date-from is refused, not silently truncated", refused)
    try:
        a, b = cli._resolve_timeline("2025-05-10T14:30:00+02:00", 5, 10)
    except click.BadParameter as exc:
        a, b = str(exc), ""
    check("the timeline anchor accepts an offset and converts it", (a, b) == ("2025-05-10T12:25:00",
                                                                           "2025-05-10T12:40:00"), f"{a} {b}")
    fc = build(exclude_id=("4600-4602,4688",))
    check("--exclude-id takes ranges", sorted(fc.get("exclude_event_ids") or []) == [4600, 4601, 4602, 4688],
          str(fc.get("exclude_event_ids")))
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
