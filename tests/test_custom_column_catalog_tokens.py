"""Every field the Custom Column "Insert field" menu offers compiles and shows that field.

Gemini audit 5-15 (Medium): field_catalog wrote "{Data[<name>]}" for every
named field.  A numeric name ("2") is read back as a POSITION, so it showed
another field; a name with "]" did not compile at all.

Expected: for event data {"Normal": "z", "A]b": "y", "2": "two"} (so "2" is field
#3) every token
the catalog offers compiles, and its value equals the value the menu
previews.  Synthetic event.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.core.custom_columns import field_catalog, CustomColumnSpec, compile_spec
    from evtx_tool.gui.models import compute_custom_values
    ev = {"record_id": 1, "event_id": 1, "timestamp": "2026-01-01T00:00:00.000000Z", "source_file": "f.evtx",
          "event_data": {"Normal": "z", "A]b": "y", "2": "two"}}
    for token, label, preview in field_catalog(ev):
        if not token.startswith("{Data"):
            continue
        try:
            c = compile_spec(CustomColumnSpec(col_id=1, title="t", template=token, kind="text"))
            vals = compute_custom_values(c, [ev])
            got = list(vals.values())[0] if isinstance(vals, dict) and vals else (vals[0] if vals else None)
            err = ""
        except Exception as e:
            got, err = None, repr(e)
        check(f"{label!r}: {token} compiles and shows {preview!r}", got == preview, err or repr(got))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
