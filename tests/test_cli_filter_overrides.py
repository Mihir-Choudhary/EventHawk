"""CLI: --event-id replaces a saved filter's Event IDs; --level never silently means "all".

Gemini audit 3-09 / 11-04 (High):
- --filter-file with event_id_expr "4624" plus --event-id 4625 kept BOTH, so
  an event had to be 4624 AND 4625: 0 events matched;
- --level "audit failure" (or any unknown word) was dropped; when nothing
  was left, levels stayed unset and EVERY level matched.

Expected: --event-id 4625 over a preset of 4624 matches 4625 events only;
--level "audit failure" keeps Audit Failure events only (Keywords bit);
an unknown --level word is refused with an error.  Synthetic events.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(eid, level=0, kw="0x8020000000000000"):
    return {"event_id": eid, "level": level, "keywords": kw, "event_data": {}, "channel": "Security",
            "computer": "HOST-A", "provider": "P", "timestamp": "2026-01-01T00:00:00Z"}


def build(**kw):
    import evtx_tool.cli as C
    args = dict(event_id=(), level=None, date_from=None, date_to=None, user=(), computer=(), source=(),
                search=(), search_mode="AND", exclude_id=(), filter_file=None)
    args.update(kw)
    return C._build_filter(**args)


def main() -> int:
    import click
    from evtx_tool.core.filters import compile_filter, empty_filter
    preset = empty_filter()
    preset["event_id_expr"] = "4624"
    pf = os.path.join(tempfile.mkdtemp(prefix="cliov_"), "preset.json")
    with open(pf, "w", encoding="utf-8") as fh:
        json.dump(preset, fh)
    fc = build(event_id=("4625",), filter_file=pf)
    f = compile_filter(fc)
    check("--event-id 4625 over a preset of 4624 matches 4625", f(ev(4625)) and not f(ev(4624)),
          f"4625 {f(ev(4625))}, 4624 {f(ev(4624))}")
    try:
        fc = build(level="audit failure")
        f = compile_filter(fc)
        ok = f(ev(4625, kw="0x8010000000000000")) and not f(ev(4624, kw="0x8020000000000000"))
        d = str(fc.get("levels"))
    except Exception as e:
        ok, d = False, repr(e)
    check("--level 'audit failure' keeps Audit Failure events only", ok, d)
    try:
        build(level="importnt")
        refused, d = False, "accepted"
    except click.BadParameter as e:
        refused, d = True, str(e)
    check("an unknown --level word is refused", refused, d)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
