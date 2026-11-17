"""The user's mappings_user.yaml is used even with unquoted numbers (Gemini 13-05).

YAML reads an unquoted 3 or 0xC000006D as an integer. The loader called .lower()
on every key, so one such key threw, the warning went to the log and the whole
file was ignored. An integer value then crashed enrich(). Expected: number keys
are matched in the form the category uses (decimal or 0x hex), number values are
used as text, an entry that cannot be used is skipped alone (and logged), and
every other entry of the file still applies. Synthetic file only.
"""
import logging
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


YAML = """\
LogonTypes:
  3: My network logon
  "10": My remote logon
StatusCodes:
  0xC000006D: My bad password
  "0xc0000064": 42
  0: My success
AccessMaskBits:
  0x1: My read bit
"""


def main() -> int:
    home = tempfile.mkdtemp(prefix="nh_")
    os.makedirs(os.path.join(home, ".evtx_tool"))
    with open(os.path.join(home, ".evtx_tool", "mappings_user.yaml"), "w", encoding="utf-8") as fh:
        fh.write(YAML)
    os.environ["USERPROFILE"] = home
    os.environ["HOME"] = home
    records = []

    class H(logging.Handler):
        def emit(self, r):
            records.append(r.getMessage())
    logging.getLogger().addHandler(H())
    try:
        from evtx_tool.analysis.normalizer import SemanticNormalizer
        n = SemanticNormalizer()

        def enrich(ed):
            ev = {"event_id": 4625, "event_data": ed}
            try:
                n.enrich(ev)
                return ev, None
            except Exception as e:
                return ev, e
        ev, e = enrich({"LogonType": "3"})
        check("unquoted 3: logon type 3 uses the user's text", ev.get("logon_type_desc") == "My network logon", f"{ev.get('logon_type_desc')!r} {e!r}")
        ev, e = enrich({"LogonType": 10})
        check("quoted \"10\" key still applies", ev.get("logon_type_desc") == "My remote logon", repr(ev.get("logon_type_desc")))
        ev, e = enrich({"Status": "0xc000006d"})
        check("unquoted 0xC000006D matches status 0xc000006d", ev.get("status_code_desc") == "My bad password", f"{ev.get('status_code_desc')!r} {e!r}")
        ev, e = enrich({"Status": "0xc0000064"})
        check("number value is used as text, no crash", e is None and ev.get("status_code_desc") == "42", f"{ev.get('status_code_desc')!r} {e!r}")
        a1, _ = enrich({"Status": "0x0"}); a2, _ = enrich({"Status": "0x00000000"})
        check("unquoted 0 replaces both bundled spellings 0x0 and 0x00000000",
              a1.get("status_code_desc") == a2.get("status_code_desc") == "My success",
              f"{a1.get('status_code_desc')!r} {a2.get('status_code_desc')!r}")
        ev, e = enrich({"AccessMask": "0x1"})
        d = ev.get("access_mask_desc") or ""
        check("unquoted 0x1 replaces bit 1's label (the bundled 0x00000001)", e is None and d == "My read bit", f"{d!r} {e!r}")
        check("no 'could not load user override' warning", not any("could not load user override" in m for m in records), str(records)[:200])
    finally:
        shutil.rmtree(home, ignore_errors=True)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
