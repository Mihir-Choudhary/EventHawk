"""HTML report drop-downs hold every whole channel, computer and event ID (Gemini audit 6-07 part 3).

The report's Channel and Computer drop-downs and each row's data-channel /
data-computer were cut to 40 and 30 characters, so two channels sharing their
first 40 characters became ONE option, and picking it showed both channels'
events.  The lists also stopped at 80 channels, 50 computers and 200 event
IDs: the rest could not be picked at all.  Expected: one option per distinct
whole value, and the rows an option selects (the report's own exact compare,
d.channel !== _F.channel) are exactly that value's events.  Synthetic events.
"""
import collections
import os
import sys
import tempfile
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


class Parse(HTMLParser):
    def __init__(self):
        super().__init__()
        self.select = None
        self.options = collections.defaultdict(list)
        self.rows = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "select":
            self.select = a.get("id")
        elif tag == "option" and self.select:
            self.options[self.select].append(a.get("value", ""))
        elif tag == "tr" and "data-idx" in a:
            self.rows.append(a)

    def handle_endtag(self, tag):
        if tag == "select":
            self.select = None


def events():
    out = []
    long_a = "Microsoft-Windows-TaskScheduler-Custom-X/Operational"     # 52 characters,
    long_b = "Microsoft-Windows-TaskScheduler-Custom-X/Diagnostic"      # same first 40
    chans = [long_a, long_b] + [f"Channel-{i:03d}" for i in range(98)]   # 100 channels
    comps = [f"workstation-{i:02d}.branch-office.example.internal" for i in range(60)]
    n = 0
    for i in range(300):                                                 # 300 event IDs
        n += 1
        out.append({"event_id": 1000 + i, "level": 4, "level_name": "Information", "provider": "P",
                    "channel": chans[i % len(chans)], "computer": comps[i % len(comps)],
                    "record_id": n, "source_file": r"C:\a\s.evtx",
                    "timestamp": "2024-01-01T00:00:00.000000Z", "event_data": {"N": str(n)}})
    return out, chans, comps


def main() -> int:
    from evtx_tool.output import exporters as X
    evs, chans, comps = events()
    p = os.path.join(tempfile.mkdtemp(prefix="htmldd_"), "r.html")
    X.export_html(evs, p)
    with open(p, encoding="utf-8") as fh:
        doc = Parse()
        doc.feed(fh.read())
    ch_opts = [o for o in doc.options["filterChannel"] if o]
    cp_opts = [o for o in doc.options["filterComputer"] if o]
    id_opts = [o for o in doc.options["filterEventID"] if o]
    check("one Channel option per distinct whole channel", sorted(ch_opts) == sorted(chans),
          f"{len(ch_opts)} options for {len(chans)} channels")
    check("one Computer option per distinct whole computer", sorted(cp_opts) == sorted(comps),
          f"{len(cp_opts)} options for {len(comps)} computers")
    check("one Event ID option per distinct event ID", len(id_opts) == 300, f"{len(id_opts)} of 300")
    check("every row is in the report", len(doc.rows) == len(evs), f"{len(doc.rows)} of {len(evs)}")
    want = collections.Counter(e["channel"] for e in evs)
    for c in chans[:2]:
        got = sum(1 for r in doc.rows if r.get("data-channel") == c)
        check(f"picking the {'first' if c == chans[0] else 'second'} long channel selects only its events",
              got == want[c] and c in ch_opts, f"{got} rows vs {want[c]} events")
    wantc = collections.Counter(e["computer"] for e in evs)
    got = sum(1 for r in doc.rows if r.get("data-computer") == comps[59])
    check("the 60th computer can be picked and selects its events",
          comps[59] in cp_opts and got == wantc[comps[59]], f"{got} vs {wantc[comps[59]]}")
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
