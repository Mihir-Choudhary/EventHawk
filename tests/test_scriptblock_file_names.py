"""Every script block gets a file of its own (audit SA-8).

The file name was the ScriptBlockId with braces removed and slashes replaced,
cut at 200 characters.  IDs that differ only by braces, by letter case (Windows
file names ignore case) or after the 200th character therefore shared one
file and the later script silently replaced the earlier one; a colon in the
ID wrote to an NTFS stream of another file.  A normal log never holds such
IDs, a crafted one can.  Expected: one file per script block, whatever the
ID; names hold only letters, digits, '-', '_' and '.'; the timeline links to
the same names; an ordinary ID keeps the name scriptblock_<ID>.txt.
Synthetic data only.
"""
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []

GUID = "0f8fad5b-d9cb-469f-a165-70867728950e"
KEYS = [
    GUID,                                   # ordinary
    GUID + "_17",                           # ordinary, no-ID fragment keyed by record number
    "{" + GUID + "}", GUID.upper(),         # same ID, other spellings
    "abc", "ABC", "{abc}", "a/b", "a\\b", "a_b",
    "x:y", "x_y", 'q"<>|?*', "..", "CON", "",
    "L" * 200 + "one", "L" * 200 + "two",
]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis.ps_extractor import writer as W
    real = W._format_scriptblock_file
    W._format_scriptblock_file = lambda acc, result: f"script of {acc!r}"
    out = Path(tempfile.mkdtemp(prefix="sbf_"))
    errors = []
    try:
        W.write_scriptblock_files({k: k for k in KEYS}, {}, out, errors=errors)
        files = sorted(os.listdir(out))
        check("one file per script block", len(files) == len(KEYS) and not errors,
              f"{len(files)} files for {len(KEYS)} script blocks; {len(errors)} write error(s)")
        check("file names hold only safe characters",
              all(re.fullmatch(r"scriptblock_[A-Za-z0-9._-]*\.txt", f) for f in files),
              f"{[f for f in files if not re.fullmatch(r'scriptblock_[A-Za-z0-9._-]*[.]txt', f)]}")
        names = {k: f"scriptblock_{W._make_safe_key(k)}.txt" for k in KEYS}
        check("names differ even when letter case is ignored",
              len({n.lower() for n in names.values()}) == len(KEYS))
        wrong = [k for k, n in names.items()
                 if not (out / n).is_file() or (out / n).read_text(encoding="utf-8") != f"script of {k!r}"]
        check("each file holds its own script, under the name the timeline links to", not wrong,
              f"{len(wrong)} wrong: {wrong[:4]}")
        check("an ordinary ID keeps its plain file name",
              names[GUID] == f"scriptblock_{GUID}.txt" and names[GUID + "_17"] == f"scriptblock_{GUID}_17.txt")
    finally:
        W._format_scriptblock_file = real
        shutil.rmtree(out, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
