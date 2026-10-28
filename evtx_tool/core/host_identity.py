"""Host identity: which Computer names in a dataset belong to the same machine.

One machine records more than one Computer name.  Windows stamps each event
with the machine's name at the moment it is written, and that name changes:
the random setup name is replaced at the end of first setup (EID 6011
records "name changed from X to Y"), and after a domain join some components
write the FQDN while others write the short name.  Measured on seven public
single-machine collections, six do this, so matching hosts by exact name
silently drops events.

Names are linked by evidence, strongest first:

* ``rename`` (automatic): an EID 6011, compared by full name, case-insensitive;
  chains are followed, including names that appear on no event.
* ``domain_suffix`` (automatic): ``X`` and ``X.<domain>`` when exactly one
  domain occurs for that short name; with several domains each link is only a
  suggestion, because they may be different machines.
* ``same_file`` (suggestion): two names in the same *local* log file.  A
  forwarded log legitimately holds many machines, so it suggests nothing;
  neither does a log with more than MAX_LOCAL_NAMES names (a collected log
  under another file name), listed in ``collected_files``.

Blank names (``(unknown)``) are never linked, and IP literals are never split
on dots or linked by suffix.  Suggestions are confirmed or rejected by the
analyst, for the session.  Pure logic, no Qt.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from itertools import combinations

UNKNOWN = "(unknown)"
# More distinct host names than this in one "local" log means it is really a
# collected log (see HostIdentity.build); it then suggests no shared-file links.
MAX_LOCAL_NAMES = 8


def is_ip_literal(s: str) -> bool:
    try:
        ipaddress.ip_address(str(s).strip().strip("[]"))
        return True
    except ValueError:
        return False


def name_key(raw: str) -> tuple[str, str]:
    """(full_key, short_key) of a Computer value.

    Strip whitespace and one trailing dot, casefold.  Blank is ``(unknown)``.
    An IP literal is kept whole (``10.0.0.5`` is never ``10``).
    """
    s = str(raw or "").strip()
    if s.endswith("."):
        s = s[:-1]
    s = s.casefold()
    if not s:
        return UNKNOWN, UNKNOWN
    if is_ip_literal(s):
        return s, s
    return s, s.split(".", 1)[0]


def is_forwarded_source(source_file: str) -> bool:
    """True if the source EVTX file is a Windows Event Forwarding collector log.

    ForwardedEvents.evtx (the default WEF target) contains events from MANY
    remote source computers — each event preserves the source machine's
    Computer field, so a single forwarded log can inflate distinct-computer
    counts dramatically.  We flag rows from such files so the UI can show
    "Forwarded? Yes" and the analyst can decide whether to filter them out.
    """
    base = os.path.basename(str(source_file or "")).lower()
    # Default name + custom-channel variants seen in the wild
    return "forwardedevents" in base or base.endswith("_forwarded.evtx")


def parse_rename(event_data) -> tuple[str, str] | None:
    """(old, new) from an EID 6011 payload ``{"Data": {"#text": [old, new]}}``.

    The two names are an unnamed <Data> pair in order.  Anything else is
    unreadable and returns None -- never guessed.
    """
    try:
        texts = event_data["Data"]["#text"]
    except (KeyError, TypeError):
        return None
    if (isinstance(texts, list) and len(texts) == 2
            and all(isinstance(t, str) and t.strip() for t in texts)):
        return texts[0].strip(), texts[1].strip()
    return None


def iso_z(ts) -> str:
    """A stored timestamp as ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` ("" if blank).

    Normal mode keeps the event's ISO form; Juggernaut stores
    ``YYYY-MM-DD HH:MM:SS.ffffff``.  One shape, so both modes compare equal.
    Fractions are padded or truncated to six digits, as JM does at parse.
    """
    s = str(ts or "").strip()
    if not s:
        return ""
    s = s.replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1]
    elif s.endswith("+00:00"):
        s = s[:-6]
    base, _, frac = s.partition(".")
    return f"{base[:19]}.{(frac + '000000')[:6]}Z"


def inputs_from_events(events) -> "tuple[list[NameStat], list[Rename], int]":
    """Host-identity input from Normal mode's event dicts, in one pass.

    Returns (names, renames, unreadable 6011 count).  A rename is EID 6011
    from provider EventLog; one whose name pair cannot be read is counted,
    never guessed.
    """
    stats: dict[tuple[str, str], list] = {}
    renames: list[Rename] = []
    bad = 0
    for ev in events:
        comp = str(ev.get("computer") or "")
        sf = str(ev.get("source_file") or "")
        ts = iso_z(ev.get("timestamp"))
        s = stats.get((comp, sf))
        if s is None:
            stats[(comp, sf)] = [1, ts, ts]
        else:
            s[0] += 1
            if ts and (not s[1] or ts < s[1]):
                s[1] = ts
            if ts > s[2]:
                s[2] = ts
        if ev.get("event_id") == 6011 and str(ev.get("provider") or "").lower() == "eventlog":
            pair = parse_rename(ev.get("event_data"))
            if pair is None:
                bad += 1
            else:
                renames.append(Rename(pair[0], pair[1], ts, sf, int(ev.get("record_id") or 0)))
    names = [NameStat(c, f, n, lo, hi) for (c, f), (n, lo, hi) in stats.items()]
    return names, renames, bad


@dataclass(frozen=True, order=True)
class NameStat:
    name: str
    source_file: str
    count: int
    first_ts: str
    last_ts: str


@dataclass(frozen=True, order=True)
class Rename:
    old: str
    new: str
    ts: str
    source_file: str
    record_id: int


@dataclass(frozen=True)
class Link:
    kind: str                       # rename | domain_suffix | same_file
    a: str                          # full key, a <= b
    b: str
    evidence: tuple = field(compare=False)
    state: str = field(compare=False, default="auto")   # auto | suggested | confirmed | rejected


@dataclass
class HostGroup:
    display_name: str
    members: list[str]              # raw names seen on events
    links: list[Link]


def link_reason(ln: Link, fmt_ts=lambda t: t) -> str:
    """Why two names are linked, in words: "rename at <time>", "domain
    suffix" or "shared file <names>".  *fmt_ts* renders the 6011 time."""
    if ln.kind == "rename":
        return f"rename at {fmt_ts(ln.evidence[0]) if ln.evidence else '?'}"
    if ln.kind == "same_file":
        return "shared file " + ", ".join(os.path.basename(f) for f in ln.evidence)
    return "domain suffix"


def _link(kind: str, x: str, y: str, evidence: tuple, state: str) -> Link:
    a, b = sorted((x, y))
    return Link(kind, a, b, evidence, state)


class _UnionFind:
    def __init__(self) -> None:
        self._p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self._p.setdefault(x, x)
        while self._p[x] != x:
            self._p[x] = self._p[self._p[x]]
            x = self._p[x]
        return x

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self._p[ry] = rx


class HostIdentity:
    def __init__(self) -> None:
        self.unreadable_renames = 0
        self.collected_files: list[str] = []     # local files treated as collected logs
        self._raw_by_node: dict[str, set[str]] = {}
        self._last_ts: dict[str, str] = {}          # raw name -> latest timestamp
        self._links: dict[Link, Link] = {}           # identity -> link with base state
        self._override: dict[Link, str] = {}         # confirmed / rejected
        self._cache = None

    # ── construction ─────────────────────────────────────────────────────────

    @classmethod
    def build(cls, names: list[NameStat], renames: list[Rename],
              unreadable_renames: int = 0) -> "HostIdentity":
        self = cls()
        self.unreadable_renames = unreadable_renames
        files: dict[str, set[str]] = {}
        for st in names:
            node = name_key(st.name)[0]
            self._raw_by_node.setdefault(node, set()).add(st.name)
            if st.last_ts > self._last_ts.get(st.name, ""):
                self._last_ts[st.name] = st.last_ts
            if node != UNKNOWN and not is_forwarded_source(st.source_file):
                files.setdefault(st.source_file, set()).add(node)

        # rename: earliest 6011 per pair is its evidence.  One old name renamed
        # to two different names is two machines from one image (a clone keeps
        # the template's setup name), so those links are only suggestions.
        pairs = []
        for r in sorted(renames, key=lambda r: r.ts):
            old, new = name_key(r.old)[0], name_key(r.new)[0]
            if old == new or UNKNOWN in (old, new) or is_ip_literal(old) or is_ip_literal(new):
                continue
            pairs.append((old, new, r))
        news_of: dict[str, set[str]] = {}
        for old, new, _r in pairs:
            news_of.setdefault(old, set()).add(new)
        for old, new, r in pairs:
            state = "auto" if len(news_of[old]) == 1 else "suggested"
            ln = _link("rename", old, new, (r.ts, r.source_file, r.record_id), state)
            self._links.setdefault(ln, ln)

        # domain suffix.  Rename endpoints take part even when they are on no
        # event: "OLD renamed NEW" plus events stamped NEW.corp.local is one
        # machine, but with only observed names the unseen NEW never reached
        # its FQDN (Codex review-1 F4).  Members still come only from names
        # seen on events (_raw_by_node).
        nodes = set(self._raw_by_node) | {n for old, new, _r in pairs for n in (old, new)}
        fqdn_by_short: dict[str, list[str]] = {}
        for n in nodes:
            if n != UNKNOWN and not is_ip_literal(n) and "." in n:
                fqdn_by_short.setdefault(n.split(".", 1)[0], []).append(n)
        for bare in nodes:
            if bare == UNKNOWN or is_ip_literal(bare) or "." in bare:
                continue
            fqdns = fqdn_by_short.get(bare, [])
            domains = {f.split(".", 1)[1] for f in fqdns}
            state = "auto" if len(domains) == 1 else "suggested"
            for f in fqdns:
                ln = _link("domain_suffix", bare, f, (f.split(".", 1)[1],), state)
                self._links.setdefault(ln, ln)

        # same local file: suggestions between names not already joined.  A log
        # with more names than one machine plausibly has (setup name, final
        # name, FQDN, a few renames) is a collected log under another file
        # name (a custom forwarding channel): pairing all its names would
        # suggest thousands of false "same machine"s.  It suggests nothing,
        # and is listed in collected_files so the UI can say so.
        auto = _UnionFind()
        for ln in self._links.values():
            if ln.state == "auto":
                auto.union(ln.a, ln.b)
        shared: dict[tuple[str, str], set[str]] = {}
        for f, fnodes in files.items():
            if len(fnodes) > MAX_LOCAL_NAMES:
                self.collected_files.append(f)
                continue
            for x, y in combinations(sorted(fnodes), 2):
                if auto.find(x) != auto.find(y):
                    shared.setdefault((x, y), set()).add(f)
        for (x, y), fs in shared.items():
            ln = _link("same_file", x, y, tuple(sorted(fs)), "suggested")
            self._links.setdefault(ln, ln)
        return self

    # ── state ────────────────────────────────────────────────────────────────

    def _state(self, ln: Link) -> str:
        return self._override.get(ln, self._links[ln].state)

    def _current(self, ln: Link) -> Link:
        base = self._links[ln]
        return Link(base.kind, base.a, base.b, base.evidence, self._state(ln))

    def confirm(self, link: Link) -> None:
        if link in self._links:
            self._override[link] = "confirmed"
            self._cache = None

    def reject(self, link: Link) -> None:
        if link in self._links:
            self._override[link] = "rejected"
            self._cache = None

    def _components(self):
        """(union-find, groups by root, suggestions by root), built once per
        state change.  Per-lookup scans made grouping quadratic in the number
        of names (5,000 hosts took over 3 s in Computer Normalisation)."""
        if self._cache is None:
            uf = _UnionFind()
            for ln in self._links:
                if self._state(ln) in ("auto", "confirmed"):
                    uf.union(ln.a, ln.b)
            members: dict[str, set[str]] = {}
            for node, raws in self._raw_by_node.items():
                members.setdefault(uf.find(node), set()).update(raws)
            links: dict[str, list[Link]] = {}
            sugg: dict[str, list[Link]] = {}
            for ln in self._links:
                st = self._state(ln)
                if st in ("auto", "confirmed"):
                    links.setdefault(uf.find(ln.a), []).append(self._current(ln))
                elif st == "suggested":
                    ra, rb = uf.find(ln.a), uf.find(ln.b)
                    if ra != rb:
                        cur = self._current(ln)
                        sugg.setdefault(ra, []).append(cur)
                        sugg.setdefault(rb, []).append(cur)
            groups: dict[str, HostGroup] = {}
            for root, raws in members.items():
                ordered = sorted(raws, key=lambda m: (m.casefold(), m))
                display = max(ordered, key=lambda m: (self._last_ts.get(m, ""), m)) if ordered else ""
                groups[root] = HostGroup(display, ordered, links.get(root, []))
            self._cache = (uf, groups, sugg)
        return self._cache

    # ── queries ──────────────────────────────────────────────────────────────

    def knows(self, raw_name: str) -> bool:
        """True if the name occurs on an event (not only inside a 6011)."""
        return name_key(raw_name)[0] in self._raw_by_node

    def group_of(self, raw_name: str) -> HostGroup:
        node = name_key(raw_name)[0]
        if node not in self._raw_by_node:
            return HostGroup(raw_name, [raw_name], [])
        uf, groups, _s = self._components()
        g = groups[uf.find(node)]
        return HostGroup(g.display_name, list(g.members), list(g.links))

    def groups(self) -> list[HostGroup]:
        _uf, groups, _s = self._components()
        return sorted((HostGroup(g.display_name, list(g.members), list(g.links))
                       for g in groups.values()),
                      key=lambda g: g.display_name.casefold())

    def suggestions_for(self, raw_name: str) -> list[Link]:
        """Unconfirmed suggestions joining this name's group to another."""
        node = name_key(raw_name)[0]
        uf, _g, sugg = self._components()
        return list(sugg.get(uf.find(node), []))
