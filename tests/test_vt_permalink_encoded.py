"""The VirusTotal link stays on the indicator's own page (Gemini 13-02).

The link was built from the response's data.id pasted into the path. An id with
"/", "?", "#" or ".." (a hostile or broken answer) moved the link to another page
of the site or added a query. Expected: the id is one encoded path segment; a
normal id is unchanged. Synthetic responses only, no network.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def resp(i, kind):
    return {"data": {"id": i, "type": kind, "attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 1}}}}


def main() -> int:
    from evtx_tool.analysis.threat_intel import _vt_parse_response as p
    h = "a" * 64
    check("normal hash id unchanged", p(resp(h, "file"))["permalink"] == f"https://www.virustotal.com/gui/file/{h}")
    check("IP id unchanged", p(resp("8.8.8.8", "ip_address"))["permalink"] == "https://www.virustotal.com/gui/ip-address/8.8.8.8")
    for bad in ("../../user/x", "x?redirect=http://e.test", "x#frag", "a/b"):
        link = p(resp(bad, "domain"))["permalink"]
        tail = link[len("https://www.virustotal.com/gui/domain/"):]
        check(f"id {bad!r} stays one path segment", link.startswith("https://www.virustotal.com/gui/domain/")
              and not any(c in tail for c in "/?#"), link)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
