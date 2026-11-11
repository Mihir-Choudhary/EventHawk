"""VirusTotal: the link matches the indicator's kind and values stay inside their URL part (audit SA-9).

The link shown for a VirusTotal result was always .../gui/file/<id>, also for
an IP address, a domain or a URL, so it opened the wrong page.  The
indicator's text (which comes from the logs) was put into the request URL
unescaped, so "a.example/../../users/x" asked VirusTotal for a different
resource than the indicator.  Expected: file, ip-address, domain and url
links; the indicator is one escaped path part.  No network use.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis import threat_intel as TI
    stats = {"malicious": 5, "suspicious": 0, "harmless": 60}
    for vt_type, ident, page in (("file", "ab" * 32, "file"), ("ip_address", "203.0.113.7", "ip-address"),
                                 ("domain", "bad.example", "domain"), ("url", "cd" * 32, "url")):
        r = TI._vt_parse_response({"data": {"id": ident, "type": vt_type,
                                            "attributes": {"last_analysis_stats": stats}}})
        check(f"{vt_type} result links to the {page} page",
              r.get("permalink") == f"https://www.virustotal.com/gui/{page}/{ident}", r.get("permalink"))
    r = TI._vt_parse_response({"data": {"id": "ab" * 32, "attributes": {"last_analysis_stats": stats}}})
    check("a result without a kind gives no link rather than a wrong one", r.get("permalink") == "",
          r.get("permalink"))
    check("the verdict is unchanged", r.get("verdict") == "malicious" and r.get("positives") == 5)

    base = TI._VT_BASE
    for kind, value in (("domains", "a.example/../../users/x"), ("ipv4", "1.2.3.4/../x?y=1#z"),
                        ("sha256", "ab/../cd"), ("domains", "a b\tc")):
        url = TI._vt_url_for(kind, value)
        tail = url[len(base) + 1:]
        check(f"{kind} value {value!r} stays one URL part",
              url.startswith(base + "/") and tail.count("/") == 1
              and not any(c in tail for c in " \t?#"), url)
    check("an ordinary domain is unchanged", TI._vt_url_for("domains", "bad.example") == base + "/domains/bad.example")
    check("an ordinary IPv6 address is unchanged",
          TI._vt_url_for("ipv6", "2001:db8::1") == base + "/ip_addresses/2001:db8::1")
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
