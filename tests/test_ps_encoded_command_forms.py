"""-EncodedCommand is decoded in every form PowerShell accepts.

Gemini audit 9-10 (Medium): the decoder took only the first flag it found
(an undecodable first value hid a valid later one), needed whitespace after
the flag ("-EncodedCommand:..." was missed) and at least 8 base64 characters
(a short command such as "ls" was missed).

Expected: each decoded; two different decoded commands are both shown.
Synthetic command lines.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def b64(s):
    return base64.b64encode(s.encode("utf-16-le")).decode()


def main() -> int:
    from evtx_tool.analysis.ps_extractor.event_parsers import _extract_encoded_command as dec
    g = b64("Get-Date -Format u")
    cases = [
        ("an undecodable first flag, then a valid one", f"powershell.exe -enc !!notb64 -enc {g}", "Get-Date -Format u"),
        ("a stray -e before the real flag", f"powershell.exe -e -NoProfile -EncodedCommand {g}", "Get-Date -Format u"),
        ("a short command (ls)", f"powershell.exe -enc {b64('ls')}", "ls"),
        ("colon syntax", f"pwsh.exe -EncodedCommand:{g}", "Get-Date -Format u"),
        ("no flag", "powershell.exe -NoProfile -File x.ps1", ""),
    ]
    ok = 0
    for name, cmd, want in cases:
        got = dec(cmd)
        good = got == want
        ok += good
        print(f"  {'PASS' if good else 'FAIL'}  {name}  -- {got!r}")
    two = dec(f"powershell.exe -enc {g} -enc {b64('whoami')}")
    good = "Get-Date -Format u" in two and "whoami" in two
    ok += good
    print(f"  {'PASS' if good else 'FAIL'}  two different encoded commands are both shown  -- {two!r}")
    n = len(cases) + 1
    print(f"{ok}/{n} checks passed")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
