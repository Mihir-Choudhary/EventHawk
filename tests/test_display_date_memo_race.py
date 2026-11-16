"""The date memo never keeps a value computed under the previous time zone.

Gemini audit 12-09 (Medium): display_hour's memo was cleared on a time-zone
change, but a background prewarm that computed a value under the OLD zone
just before the change wrote it into the cleared memo afterwards, so the
date tree showed the old zone's date until the next change.

Expected: with the zone changed while a value is being computed, the
memo holds only the new zone's value.  The interleaving is forced with a
stand-in apply_tz.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    import evtx_tool.gui.models as M
    ts = "2026-02-17T21:30:00Z"
    M.set_tz_config("UTC")
    real = M.apply_tz
    state = {"n": 0}

    def slow_apply(raw):
        # The first call runs under UTC; the zone changes before it returns.
        state["n"] += 1
        if state["n"] == 1:
            v = real(raw)
            M.set_tz_config("specific", "Asia/Kolkata")
            M.display_hour("2000-01-01T00:00:00Z")     # another caller sees the new zone first
            return v
        return real(raw)
    M.apply_tz = slow_apply
    try:
        M.display_hour(ts)                            # computed under UTC, finishes after the change
    finally:
        M.apply_tz = real
    got = M.display_hour(ts)
    want = real(ts)[:13].lower()
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  after the change the memo gives the new zone's hour  -- {got!r} (want {want!r})")
    M.set_tz_config("UTC")
    print(f"{int(ok)}/1 checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
