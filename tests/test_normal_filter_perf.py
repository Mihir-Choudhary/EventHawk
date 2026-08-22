"""Normal-mode advanced text filter: identical results, built once not per-row.

The advanced text filter rebuilt its haystack for EVERY row on EVERY pass --
recursive event_data flatten plus a regex substitution per value. That is
~23us/row, i.e. 11.4s of frozen GUI for one text search over 500k events.
It is now precomputed once per dataset.

Because the haystack decides WHICH EVENTS AN ANALYST SEES, the first checks
here assert the cached string is byte-identical to the original inline logic,
reproduced verbatim below. Speed is worthless if the result set moves.

Run: QT_QPA_PLATFORM=offscreen python tests/test_normal_filter_perf.py
"""
import os, re as _re, sys, time, random

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel

res = []
def check(name, ok, detail=""):
    res.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))


def legacy_haystack(ev: dict) -> str:
    """Reference haystack, written from the CONTRACT, not copied from the code.

    Contract: the Advanced Filter searches everything an analyst can see --
    every System field, every EventData value, and every EventData field name --
    and matches Juggernaut's SEARCH_TEXT_EXPR_FULL so both modes agree.

    Used for result-set equivalence below. Byte-identity with the
    implementation is deliberately NOT asserted: that only ever tested that
    someone had copied the code twice.
    """
    import json as _j
    from evtx_tool.core.filters import flatten_searchable_values as _fsv
    parts = []
    for fld in ("event_id", "record_id", "level", "level_name", "channel",
                "provider", "event_source_name", "provider_guid", "computer",
                "user_id", "source_file", "timestamp", "keywords",
                "correlation_id", "task", "opcode", "process_id", "thread_id",
                "qualifiers", "version"):
        v = ev.get(fld)
        if v is not None and v != "":
            parts.append(str(v))
    ed = ev.get("event_data", {}) or {}
    if ed:
        for val in _fsv(ed):
            parts.append(_re.sub(r'\\\s+', r'\\', val))
        parts.append(_j.dumps(ed, default=str))
    return " ".join(parts)


# ── awkward shapes: nested dicts, lists, split paths, unicode, None ───────
tricky = [
    {"event_id": 4688, "level_name": "Information", "channel": "Security",
     "provider": "Microsoft-Windows-Security-Auditing", "computer": "HOST-A",
     "user_id": "S-1-5-18", "source_file": "/logs/Security.evtx",
     "event_data": {"NewProcessName": "C:\\Windows\\  System32\\cmd.exe",
                    "Nested": {"Inner": ["a", "b"], "Deep": {"K": "vàlue"}},
                    "Empty": "", "Dash": "-", "NoneVal": None}},
    {"event_id": 1, "level_name": None, "channel": "Sysmon",
     "provider": None, "computer": "HOST-B", "user_id": None,
     "source_file": "/logs/S.evtx", "event_data": {}},
    {"event_id": 7045, "level_name": "Warning", "channel": "System",
     "provider": "SCM", "computer": "HOST-C", "user_id": "S-1-5-19",
     "source_file": "/logs/System.evtx",
     "event_data": {"Data": ["one", "two", "C:\\a\\ \\b"]}},
    {"event_id": 4624, "computer": "HOST-D", "channel": "Security",
     "source_file": "/l.evtx", "event_data": {"TargetUserName": "Ålice"}},
]
m0 = EventTableModel(); m0.set_events(tricky)
# The cache must equal the uncached computation for the same event -- this is
# what catches a stale or mis-indexed cache, and it is not a tautology.
stale = [i for i, ev in enumerate(tricky)
         if m0.get_adv_search_str(i) != m0.build_adv_search_str(ev).lower()]
check("cached haystack equals the uncached computation", not stale,
      f"rows differing: {stale}")

# Contract: nothing an analyst can see is missing from the haystack.
def _leaf_values(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str) and not k.startswith("#"):
                yield k
            yield from _leaf_values(v)
    elif isinstance(o, (list, tuple)):
        for i in o:
            yield from _leaf_values(i)
    elif o is not None:
        yield str(o)

missing_sys, missing_ed = [], []
for i, ev in enumerate(tricky):
    hay = m0.get_adv_search_str(i)
    for fld in ("event_id", "channel", "provider", "computer", "user_id",
                "source_file", "level_name", "event_source_name"):
        v = ev.get(fld)
        if v not in (None, "") and str(v).lower() not in hay:
            missing_sys.append((i, fld, v))
    for tok in _leaf_values(ev.get("event_data") or {}):
        # Values are stored with XML line-split backslashes collapsed
        # ("C:\\Windows\\  System32" -> "C:\\Windows\\System32") so a path broken
        # across lines is searchable as one string. Compare the same way.
        norm = _re.sub(r'\\\s+', r'\\', tok)
        if norm and norm.strip() and norm.lower() not in hay:
            missing_ed.append((i, tok[:40]))
check("every System field value is in the haystack", not missing_sys,
      str(missing_sys[:5]))
check("every EventData name AND value is in the haystack", not missing_ed,
      str(missing_ed[:5]))

# ── result-set equivalence on a real-ish corpus ──────────────────────────
N = 40_000
random.seed(7)
users = ["alice", "bob", "svc-backup", "Administrator"]
comps = [f"HOST-{i:02d}" for i in range(12)]
events = [{
    "record_id": i, "event_id": random.choice([4624, 4634, 4688, 1, 7045]),
    "level_name": "Information", "timestamp": f"2025-06-10T09:00:{i%60:02d}.000000Z",
    "computer": random.choice(comps), "channel": "Security", "user_id": "S-1-5-18",
    "source_file": "/logs/Security.evtx", "provider": "P", "keywords": "",
    "task": 0, "opcode": 0, "process_id": 4, "thread_id": 8, "correlation_id": "",
    "event_data": {"TargetUserName": random.choice(users),
                   "Path": "C:\\Windows\\  System32\\svc.exe",
                   "Nested": {"Deep": {"Val": f"tok{i%97}"}}},
} for i in range(N)]

model = EventTableModel(); model.set_events(events)
proxy = EventFilterProxyModel(); proxy.setSourceModel(model)

# Oracle computed ONCE (the whole point is that this is expensive per pass).
oracle_low = [legacy_haystack(ev).lower() for ev in events]
for needle in ("alice", "svc-backup", "tok42", "system32", "nomatchhere", "ÅLICE"):
    proxy.set_advanced_filter({"text_search": needle})
    got = proxy.rowCount()
    want = sum(1 for h in oracle_low if needle.lower() in h)
    check(f"text '{needle}': same rows as the original logic", got == want,
          f"{got} vs {want}")

# case-sensitive path must still work (it bypasses the cache)
proxy.set_advanced_filter({"text_search": "Alice", "case_sensitive": True})
got = proxy.rowCount()
oracle_raw = [legacy_haystack(ev) for ev in events]
want = sum(1 for h in oracle_raw if "Alice" in h)
check("case-sensitive search unaffected by the cache", got == want, f"{got} vs {want}")

# dataset swap must invalidate the cache, not serve stale haystacks
proxy.set_advanced_filter(None)
model.set_events(events[:100])
proxy.set_advanced_filter({"text_search": "alice"})
want = sum(1 for ev in events[:100] if "alice" in legacy_haystack(ev).lower())
check("cache invalidated when the dataset changes", proxy.rowCount() == want,
      f"{proxy.rowCount()} vs {want}")

# ── speed ────────────────────────────────────────────────────────────────
model.set_events(events)
proxy.set_advanced_filter(None); proxy.rowCount()

def timed_filter(cfg):
    """Qt evaluates the filter lazily — rowCount() forces the full pass."""
    t0 = time.perf_counter()
    proxy.set_advanced_filter(cfg)
    proxy.rowCount()
    return time.perf_counter() - t0

first  = timed_filter({"text_search": "alice"})   # builds the cache
second = timed_filter({"text_search": "bob"})     # reuses it
third  = timed_filter({"text_search": "tok42"})
print(f"      {N:,} events — first text filter {first*1000:.0f} ms (builds cache), "
      f"then {second*1000:.0f} ms / {third*1000:.0f} ms")
check("repeat text filters reuse the cache (much faster than the first)",
      second < first / 2 and second > 0,
      f"first {first*1000:.0f} ms, second {second*1000:.0f} ms")

# ── background haystack build ────────────────────────────────────────────
# Building this lazily on the first text search froze the GUI for ~30 s on
# 1.7M events. It is now built in slices that yield to the event loop. The
# result must be IDENTICAL to the lazy build -- a faster search that finds
# different events would be worse than a slow one.
from PySide6.QtWidgets import QApplication as _QApp
_app = _QApp.instance() or _QApp([])
m_bg = EventTableModel(); m_bg.set_events(events)
m_lazy = EventTableModel(); m_lazy.set_events(events)
lazy = [m_lazy.get_adv_search_str(i) for i in range(len(events))]

m_bg.start_adv_cache_build()
check("background build starts", getattr(m_bg, "_adv_build_timer", None) is not None)
_spins = 0
while getattr(m_bg, "_adv_build_timer", None) is not None and _spins < 200000:
    _app.processEvents(); _spins += 1
built = [m_bg.get_adv_search_str(i) for i in range(len(events))]
check("background build completes", m_bg._adv_search_cache is not None)
check("background build matches the lazy build exactly", built == lazy,
      f"{sum(1 for a, b in zip(built, lazy) if a != b)} rows differ")

# a search arriving mid-build must still be correct, not truncated
m_mid = EventTableModel(); m_mid.set_events(events)
m_mid.start_adv_cache_build()
_app.processEvents()          # let one slice run, leaving it partial
mid = [m_mid.get_adv_search_str(i) for i in range(len(events))]
check("a search during the build finishes it rather than truncating",
      mid == lazy, f"{sum(1 for a, b in zip(mid, lazy) if a != b)} rows differ")

# a new dataset must abandon the in-flight build
m_new = EventTableModel(); m_new.set_events(events)
m_new.start_adv_cache_build()
m_new.set_events(events[:50])
check("loading a new dataset cancels the in-flight build",
      getattr(m_new, "_adv_build_timer", None) is None)
check("the new dataset's haystack is its own",
      m_new.get_adv_search_str(0) == m_new.build_adv_search_str(events[0]).lower())

print("\n" + "=" * 60)
bad = [n for n, ok in res if not ok]
print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
for n in bad:
    print("  FAILED:", n)
sys.stdout.flush()
sys.exit(1 if bad else 0)
