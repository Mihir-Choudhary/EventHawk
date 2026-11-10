"""PowerShell script-block TXT keeps the script's own line breaks (Codex FO-13).

The TXT writer wrote in text mode: on Windows every LF became CRLF, so a
script's original CRLF came out as CR CR LF (extra blank lines; 97,067 pairs
in 147 real blocks) and the file no longer held the script's exact text.
Expected: the assembled script appears in the TXT byte-for-byte.  Synthetic.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis.ps_extractor.models import ScriptBlockAccumulator, ScriptFragment
    from evtx_tool.analysis.ps_extractor.writer import write_scriptblock_files
    script = "Write-Host A\r\nWrite-Host B\r\n\tif ($x) {\n  lone-LF line\n}\rlone-CR end"
    acc = ScriptBlockAccumulator(script_block_id="{11111111-2222-3333-4444-555555555555}",
                                 path="", computer="PC")
    acc.fragments[1] = ScriptFragment(1, 1, script, "2024-01-02T03:04:05Z", 7, 5, "1", "", "")
    out = Path(tempfile.mkdtemp(prefix="ps_txt_"))
    errs: list = []
    write_scriptblock_files({acc.script_block_id: acc}, {}, out, errors=errs)
    files = list(out.glob("scriptblock_*.txt"))
    check("one TXT written, no error", len(files) == 1 and not errs, f"{len(files)} {errs}")
    if files:
        data = files[0].read_bytes()
        check("the assembled script is in the TXT byte-for-byte",
              acc.assemble().encode("utf-8") in data)
        check("no CR CR LF anywhere", b"\r\r\n" not in data)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
