"""Copies of a log collapse; two different records with the same ID do not.

Gemini audit 1-05 (Medium): collapse_copies treated two records as copies when
host, channel, event ID, timestamp and record ID matched and event_data was
equal -- ignoring every other <System> field.  Two records differing in
provider, level, user, process or correlation ID were merged and one was
lost from counts (correlation, IOCs).

Expected:
- synthetic: two records equal in identity and event_data but different in
  provider / level / user_id / process_id are both kept;
- real: corpus logs loaded with their "- Copy" files collapse exactly as
  under the old identity + event_data rule (true copies are unaffected).
Real logs read in place (needs EVTX_TEST_LOGS).
"""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.core.record_identity import collapse_copies
    base = {"computer": "HOST-A", "channel": "System", "event_id": 104, "record_id": 1, "event_record_id": 1,
            "timestamp": "2026-03-01T12:00:00.000000Z", "event_data": {}, "level": 4, "task": 0, "opcode": 0,
            "keywords": "0x0", "user_id": "S-1-5-18", "provider": "Prov-A", "process_id": 640, "thread_id": 1,
            "correlation_id": "", "event_source_name": "", "source_file": "a.evtx"}
    for field, val in (("provider", "Prov-B"), ("level", 2), ("user_id", "S-1-5-21-0-0-0-1000"),
                       ("process_id", 4120), ("correlation_id", "{X}")):
        b = dict(base, source_file="b.evtx", **{field: val})
        kept, _ = collapse_copies([dict(base), b])
        check(f"records differing only in {field} are both kept", len(kept) == 2, f"kept {len(kept)}")
    kept, _ = collapse_copies([dict(base), dict(base, source_file="b.evtx")])
    check("an exact copy still collapses", len(kept) == 1, f"kept {len(kept)}")

    root = os.environ.get("EVTX_TEST_LOGS")
    if root and os.path.isdir(root):
        from evtx_tool.core.engine import _worker_parse_file
        from evtx_tool.core.filters import empty_filter
        pairs = []
        for c in sorted(glob.glob(os.path.join(root, "**", "* - Copy.evtx"), recursive=True)):
            o = c.replace(" - Copy.evtx", ".evtx")
            if os.path.isfile(o) and os.path.getsize(o) == os.path.getsize(c) and os.path.getsize(o) < 25 * 2**20:
                pairs.append((o, c))
            if len(pairs) == 4:
                break
        evs = []
        for o, c in pairs:
            eo = _worker_parse_file({"filepath": o, "filter_config": empty_filter()})["events"]
            ec = _worker_parse_file({"filepath": c, "filter_config": empty_filter()})["events"]
            evs += eo + ec
        kept, copies = collapse_copies(evs)
        # Reference: the old rule (identity + event_data only), written here.
        from evtx_tool.core.record_identity import record_identity
        seen = set()
        ref = 0
        for e in evs:
            i = record_identity(e)
            k = None if i is None else (i, repr(sorted((e.get("event_data") or {}).items())))
            if k is None or k not in seen:
                ref += 1
                if k is not None:
                    seen.add(k)
        check("real logs with their copies collapse exactly as under the old rule",
              len(pairs) > 0 and len(kept) == ref and len(kept) < len(evs),
              f"{len(pairs)} pairs, {len(evs)} records, kept {len(kept)}, old rule {ref}")
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
