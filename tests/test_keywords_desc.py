"""The Keywords label names the keyword bits Windows defines, not the opposite outcome.

Found while widening text search (2026-11-02): the semantic label shown next to
Keywords in the details pane came from an exact-value table that had the audit
outcome reversed -- 0x8020000000000000 (bit 53, Audit Success: a successful
logon) read "Audit Failure (SQM)" and 0x8010000000000000 (bit 52, Audit
Failure) read "Audit Success".  Expected: the label is decoded from the
standard keyword bits (0x0010.. Audit Failure, 0x0020.. Audit Success,
0x0040.. Correlation Hint, 0x0080.. Classic, 0x0008.. SQM, 0x0004.. WDI
Diagnostic, 0x0002.. WDI Context, 0x0001.. Response Time); bits Windows does
not define get no label (never a guessed one); 0 reads "No Keywords".
Synthetic values only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def label(kw):
    from evtx_tool.analysis.normalizer import SemanticNormalizer
    ev = {"keywords": kw, "event_data": {}}
    SemanticNormalizer.get().enrich(ev)
    return ev.get("keywords_desc")


def main() -> int:
    cases = [
        ("0x8020000000000000", "Audit Success", "Failure"),   # 4624 in the Security log
        ("0x8010000000000000", "Audit Failure", "Success"),   # 4625
        ("0x4020000000000000", "Audit Success", "Failure"),
        ("0x0010000000000000", "Audit Failure", "Success"),
        ("0x8080000000000000", "Classic", "Audit"),           # classic providers (System log)
        ("0x0", "No Keywords", "Audit"),
    ]
    for kw, want, never in cases:
        got = label(kw) or ""
        check(f"{kw} reads {want!r}", want in got and never not in got, repr(got))
    got = label("0x8000000000000000")
    check("a bit Windows does not define gets no label", not got, repr(got))
    got = label("0x0060000000000000") or ""
    check("several bits are all named", "Audit Success" in got and "Correlation Hint" in got, repr(got))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
