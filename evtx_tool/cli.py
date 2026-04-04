"""
CLI entry point for EventHawk v1.3.

Commands:
  parse       - Parse EVTX files with profiles/filters + analysis pipeline
  diff        - Compare baseline vs incident EVTX sets
  profiles    - Manage DFIR profiles (list/show/create/delete/import/export)
  benchmark   - Benchmark parsing speed
  interactive - Interactive wizard

New flags on parse:
  --attack / --no-attack     MITRE ATT&CK tagging (default: ON)
  --ioc                      Extract IOCs after parsing
  --correlate                Run attack-chain correlation engine
  --timeline-anchor TEXT     Set pivot time for timeline investigation
  --timeline-before INT      Minutes before anchor (default 5)
  --timeline-after  INT      Minutes after anchor  (default 30)
"""

from __future__ import annotations

import logging
import operator as _operator
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

_BY_TIMESTAMP = _operator.methodcaller("get", "timestamp", "")

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

import io
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from evtx_tool.core.engine import ProcessingEngine
from evtx_tool.core.filters import empty_filter, load_filter, save_filter, filter_from_dict
from evtx_tool.core.parser import get_backend
from evtx_tool.output.exporters import export, EXPORT_FORMATS
from evtx_tool.profiles.manager import ProfileManager
from evtx_tool.tui import EVTXParserTUI

console = Console(legacy_windows=False, emoji=False)


# ── Logging ───────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    log_dir = Path("evtx_tool_logs")
    log_dir.mkdir(exist_ok=True)
    handlers = [logging.FileHandler(log_dir / "evtx_parser.log", encoding="utf-8")]
    if verbose:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers, force=True,
    )


# ── File collection ───────────────────────────────────────────────────────────

def _collect_evtx_files(paths: list[str], recursive: bool = True) -> list[str]:
    files: list[str] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            pattern = "**/*.evtx" if recursive else "*.evtx"
            files.extend(sorted(str(f) for f in path.glob(pattern)))
        elif path.is_file() and path.suffix.lower() == ".evtx":
            files.append(str(path))
        elif "*" in p or "?" in p:
            import glob as _glob
            files.extend(sorted(_glob.glob(p, recursive=recursive)))
        else:
            console.print(f"[yellow]Warning: {p} not found or not an EVTX file[/yellow]")
    seen: set[str] = set()
    result: list[str] = []
    for f in files:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


# ── Filter builder ────────────────────────────────────────────────────────────

def _build_filter(
    event_id, level, date_from, date_to,
    user, computer, source, search, search_mode,
    exclude_id, filter_file,
) -> dict:
    fc = load_filter(filter_file) if filter_file else empty_filter()

    if event_id:
        ids: list[int] = []
        for spec in ",".join(event_id).split(","):
            spec = spec.strip()
            if "-" in spec and spec.count("-") == 1 and not spec.startswith("-"):
                lo, hi = spec.split("-", 1)
                try:
                    ids.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    pass
            elif spec.isdigit():
                ids.append(int(spec))
            elif spec:
                # BUG 27 fix: warn on unrecognised event-ID specs instead of silently dropping
                click.echo(f"Warning: unrecognised event-ID spec '{spec}' — skipped", err=True)
        if ids:
            fc["event_ids"] = ids

    if exclude_id:
        excl = [int(x.strip()) for x in ",".join(exclude_id).split(",") if x.strip().isdigit()]
        if excl:
            fc["exclude_event_ids"] = excl

    level_map = {
        "critical": [1], "error": [2], "warning": [3], "warn": [3],
        "information": [4], "info": [4], "verbose": [5], "logalways": [0],
    }
    if level:
        levels: list[int] = []
        for lvl in level.lower().split(","):
            lvl = lvl.strip()
            if lvl in level_map:
                levels.extend(level_map[lvl])
            elif lvl.isdigit():
                levels.append(int(lvl))
        if levels:
            fc["levels"] = list(set(levels))

    if date_from: fc["date_from"] = date_from
    if date_to:   fc["date_to"]   = date_to
    if user:      fc["users"]     = list(user)
    if computer:  fc["computers"] = list(computer)
    if source:    fc["sources"]   = list(source)
    if search:
        fc["text_search"] = list(search)
        fc["search_mode"] = search_mode.upper()
    return fc


def _resolve_timeline(anchor: str, before_mins: int, after_mins: int) -> tuple[str, str]:
    """Parse anchor timestamp + window into ISO date_from / date_to."""
    clean = anchor.strip().rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
                "%Y-%m-%d"):
        try:
            dt = datetime.strptime(clean, fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    else:
        raise click.BadParameter(
            f"Cannot parse timeline anchor '{anchor}'. "
            "Use: 2026-02-21T14:30:00  or  '2026-02-21 14:30:00'"
        )
    date_from = (dt - timedelta(minutes=before_mins)).strftime("%Y-%m-%dT%H:%M:%S")
    date_to   = (dt + timedelta(minutes=after_mins)).strftime("%Y-%m-%dT%H:%M:%S")
    return date_from, date_to


def _set_priority(priority: str) -> None:
    try:
        import psutil
        proc    = psutil.Process(os.getpid())
        mapping = {
            "low":    getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS",
                              getattr(psutil, "IDLE_PRIORITY_CLASS", 0)),
            "normal": psutil.NORMAL_PRIORITY_CLASS,
            "high":   psutil.HIGH_PRIORITY_CLASS,
        }
        proc.nice(mapping.get(priority.lower(), psutil.NORMAL_PRIORITY_CLASS))
    except Exception:
        pass


# ── Post-parse analysis pipeline ──────────────────────────────────────────────

def _run_analysis(
    events: list[dict],
    do_attack:    bool,
    do_ioc:       bool,
    do_correlate: bool,
) -> tuple[dict | None, dict | None, list[dict] | None]:
    """
    All steps run in the main process on the already-collected events list.
    Zero impact on parse worker performance.
    Returns (attack_summary, iocs, chains).
    """
    attack_summary: dict | None       = None
    iocs:           dict | None       = None
    chains:         list[dict] | None = None

    # 1. ATT&CK tagging — sigma rules + context enrichment in one pass
    if do_attack:
        from evtx_tool.analysis.attack_mapping import enrich_and_summarize
        attack_summary = enrich_and_summarize(events)
        console.print(
            f"[cyan]ATT&CK:[/cyan] {attack_summary.get('total_tagged',0):,} tagged | "
            f"{len(attack_summary.get('by_tactic',{}))} tactics | "
            f"{len(attack_summary.get('by_technique',{}))} techniques"
        )

    # 3. IOC extraction (opt-in)
    if do_ioc:
        from evtx_tool.analysis.ioc_extractor import extract_iocs
        t0   = time.monotonic()
        iocs = extract_iocs(events)
        elapsed = time.monotonic() - t0
        s    = iocs.get("summary", {})
        console.print(
            f"[cyan]IOCs:[/cyan] extracted in {elapsed:.2f}s -- "
            f"IPv4:{s.get('ipv4',0)}  SHA256:{s.get('sha256',0)}  "
            f"MD5:{s.get('md5',0)}  Users:{s.get('users',0)}  "
            f"Computers:{s.get('computers',0)}  Processes:{s.get('processes',0)}"
        )

    # 4. Correlation engine (opt-in, O(n log n) already sorted)
    if do_correlate:
        from evtx_tool.analysis.correlator import correlate
        t0     = time.monotonic()
        chains = correlate(events)
        elapsed = time.monotonic() - t0
        crit   = sum(1 for c in chains if c["severity"] == "critical")
        high   = sum(1 for c in chains if c["severity"] == "high")
        console.print(
            f"[cyan]Correlation:[/cyan] {len(chains)} chains in {elapsed:.2f}s "
            f"({crit} critical, {high} high)"
        )
        sev_col = {"critical": "red", "high": "yellow", "medium": "magenta", "low": "cyan"}
        for chain in chains[:5]:
            sc = sev_col.get(chain["severity"], "white")
            console.print(
                f"  [{sc}][{chain['severity'].upper()}][/{sc}] "
                f"{chain['rule_name']} -- "
                f"{', '.join(chain['computers']) or '?'}"
            )
        if len(chains) > 5:
            console.print(f"  [dim]... and {len(chains)-5} more[/dim]")

    return attack_summary, iocs, chains


# ── CLI root ──────────────────────────────────────────────────────────────────

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option("1.3.0", prog_name="EventHawk")
def cli():
    """EventHawk v1.3 -- High-performance DFIR EVTX analysis."""
    pass


# ── parse command ─────────────────────────────────────────────────────────────

@cli.command("parse")
@click.argument("paths", nargs=-1, required=True, metavar="FILE_OR_DIR...")
# Profile / filter
@click.option("--profile",     "-p", multiple=True,
              help="DFIR profile (repeat or use 'all').")
@click.option("--filter-file", "-F", default=None, help="Load filter from JSON file.")
@click.option("--event-id",    "-e", multiple=True,
              help="Filter Event IDs: '4624,4625' or '4600-4650'.")
@click.option("--exclude-id",        multiple=True, help="Exclude Event IDs.")
@click.option("--level",       "-l", default=None,
              help="Level: critical,error,warning,info,verbose.")
@click.option("--date-from",         default=None, help="Start datetime (ISO).")
@click.option("--date-to",           default=None, help="End datetime (ISO).")
@click.option("--user",        "-u", multiple=True, help="Filter by username/SID.")
@click.option("--computer",    "-c", multiple=True, help="Filter by computer name.")
@click.option("--source",      "-s", multiple=True, help="Filter by source/provider.")
@click.option("--search",      "-q", multiple=True, help="Free-text search terms.")
@click.option("--search-mode",       default="AND", show_default=True,
              type=click.Choice(["AND", "OR", "NOT"], case_sensitive=False))
# Timeline
@click.option("--timeline-anchor",  default=None,
              help="Pivot time (e.g. '2026-02-21T14:30:00'). Sets a time window.")
@click.option("--timeline-before",  default=5, show_default=True, type=int,
              help="Minutes before the timeline anchor.")
@click.option("--timeline-after",   default=30, show_default=True, type=int,
              help="Minutes after the timeline anchor.")
# Output
@click.option("--output", "-o",     default=None,
              help="Output file (.html .csv .json .xml .pdf).")
@click.option("--format", "fmt",
              type=click.Choice(list(EXPORT_FORMATS.keys()), case_sensitive=False),
              default=None, help="Override output format.")
@click.option("--save-filter",      "save_filter_path", default=None,
              help="Save active filter config to JSON file.")
# Analysis pipeline (all run post-parse in main process -- zero parse overhead)
@click.option("--attack/--no-attack", default=True, show_default=True,
              help="MITRE ATT&CK tagging on every matched event.")
@click.option("--ioc",               is_flag=True, default=False,
              help="Extract IOCs (IPs, hashes, users, commands, paths).")
@click.option("--correlate",         is_flag=True, default=False,
              help="Run attack-chain correlation engine (10 rules).")
# Engine
@click.option("--max-threads",       type=int, default=None,
              help="Max worker processes (default: CPU-1).")
@click.option("--cpu-limit",         type=float, default=85.0, show_default=True)
@click.option("--ram-limit",         type=float, default=90.0, show_default=True)
@click.option("--priority",
              type=click.Choice(["low", "normal", "high"], case_sensitive=False),
              default="normal", show_default=True)
@click.option("--no-recursive",      is_flag=True, default=False)
@click.option("--limit",             type=int, default=None,
              help="Cap output at N events.")
@click.option("--no-tui",            is_flag=True, default=False)
@click.option("--verbose",    "-v",  is_flag=True, default=False)
def parse_cmd(
    paths, profile, filter_file, event_id, exclude_id, level,
    date_from, date_to, user, computer, source, search, search_mode,
    timeline_anchor, timeline_before, timeline_after,
    output, fmt, save_filter_path,
    attack, ioc, correlate,
    max_threads, cpu_limit, ram_limit, priority,
    no_recursive, limit, no_tui, verbose,
):
    """Parse EVTX files -- profiles, filters, ATT&CK, IOC, correlation, timeline."""
    _setup_logging(verbose)
    _set_priority(priority)

    files = _collect_evtx_files(list(paths), recursive=not no_recursive)
    if not files:
        console.print("[red]No EVTX files found.[/red]")
        raise SystemExit(1)
    console.print(
        f"[cyan]Found {len(files)} EVTX file(s)[/cyan] | "
        f"Backend: [green]{get_backend()}[/green]"
    )

    # ── Timeline mode ─────────────────────────────────────────────────────
    timeline_mode = bool(timeline_anchor)
    if timeline_mode:
        date_from, date_to = _resolve_timeline(
            timeline_anchor, timeline_before, timeline_after
        )
        console.print(
            f"[cyan]Timeline window:[/cyan] {date_from} --> {date_to} "
            f"({timeline_before}m before, {timeline_after}m after anchor)"
        )
        if not profile and not event_id:
            console.print(
                "[dim]Timeline mode: no profile/event-id filter -- "
                "showing ALL events in window sorted by time[/dim]"
            )

    # ── Build filter ──────────────────────────────────────────────────────
    fc = _build_filter(
        event_id, level, date_from, date_to,
        user, computer, source, search, search_mode,
        exclude_id, filter_file,
    )

    # ── Apply profiles ────────────────────────────────────────────────────
    pm            = ProfileManager()
    profile_names = list(profile)
    if any(p.lower() == "all" for p in profile_names):
        profile_names = pm.list_names()
    if profile_names:
        fc = pm.build_filter(profile_names, base_filter=fc)
        console.print(f"[magenta]Profiles: {', '.join(profile_names)}[/magenta]")
        if fc.get("event_ids"):
            console.print(f"[dim]Profile event IDs: {len(fc['event_ids'])}[/dim]")

    if save_filter_path:
        save_filter(fc, save_filter_path)
        console.print(f"[dim]Filter saved -> {save_filter_path}[/dim]")

    # ── Filter description for TUI ────────────────────────────────────────
    filter_parts: list[str] = []
    if timeline_mode:
        filter_parts.append(f"Timeline: {date_from}..{date_to}")
    if fc.get("event_ids"):
        sample = fc["event_ids"][:5]
        more   = f"+{len(fc['event_ids'])-5}" if len(fc["event_ids"]) > 5 else ""
        filter_parts.append(f"EventID: {','.join(map(str,sample))}{more}")
    if fc.get("users"):
        filter_parts.append(f"User: {','.join(fc['users'])}")
    if fc.get("computers"):
        filter_parts.append(f"Computer: {','.join(fc['computers'])}")
    if fc.get("text_search"):
        filter_parts.append(
            f"Search: {' '.join(fc['text_search'])} [{fc.get('search_mode','AND')}]"
        )
    filter_str = " | ".join(filter_parts) if filter_parts else "None (all events)"

    # ── Engine ────────────────────────────────────────────────────────────
    engine = ProcessingEngine(
        max_workers=max_threads,
        cpu_limit=cpu_limit,
        ram_limit=ram_limit,
    )

    if no_tui:
        console.print(f"[dim]Processing {len(files)} files...[/dim]")
        all_events = engine.run(files, fc)
        console.print(f"[green]Done: {len(all_events):,} events matched[/green]")
    else:
        tui = EVTXParserTUI(console=console)
        tui.set_context(profiles=profile_names, filters=filter_str)
        engine._on_progress = tui.update_state
        tui.start()
        try:
            all_events = engine.run(files, fc)
        finally:
            state_snap = engine.state.snapshot()
            tui.stop()
            time.sleep(0.4)
            tui.print_summary(all_events, state_snap)

    # ── Sort by timestamp (always -- required for timeline + correlation) ─
    if all_events:
        all_events.sort(key=_BY_TIMESTAMP)

    # ── Limit output (BUG 26 fix: apply BEFORE analysis so IOCs/chains reflect
    #    the same events shown in the report table) ─────────────────────────
    if limit and len(all_events) > limit:
        console.print(
            f"[dim]Limiting to first {limit:,} events (--limit) before analysis[/dim]"
        )
        all_events = all_events[:limit]

    # ── Post-parse analysis ───────────────────────────────────────────────
    attack_summary, iocs_result, chains = _run_analysis(
        all_events,
        do_attack    = attack,
        do_ioc       = ioc,
        do_correlate = correlate,
    )

    # ── Export ────────────────────────────────────────────────────────────
    if output:
        count = export(
            all_events, output, fmt,
            attack_summary = attack_summary,
            iocs           = iocs_result,
            chains         = chains,
        )
        console.print(f"[green]Exported {count:,} events -> {output}[/green]")
    elif all_events:
        if len(all_events) <= 100:
            _print_events_table(all_events)
        else:
            console.print(
                f"[dim]{len(all_events):,} events matched. "
                f"Use --output to save.[/dim]"
            )


# ── diff command ──────────────────────────────────────────────────────────────

@cli.command("diff")
@click.argument("baseline", metavar="BASELINE_PATH")
@click.argument("incident", metavar="INCIDENT_PATH")
@click.option("--profile",     "-p", multiple=True,
              help="Profiles to apply to both sets (or 'all').")
@click.option("--output",      "-o", default=None,
              help="Output file (.html / .json / .csv).")
@click.option("--format",      "fmt",
              type=click.Choice(list(EXPORT_FORMATS.keys()), case_sensitive=False),
              default=None)
@click.option("--spike-factor",      default=3.0, show_default=True,
              help="Volume spike threshold (incident/baseline ratio).")
@click.option("--max-threads",       type=int, default=None)
@click.option("--verbose",     "-v", is_flag=True, default=False)
def diff_cmd(baseline, incident, profile, output, fmt, spike_factor, max_threads, verbose):
    """
    Compare baseline vs incident EVTX sets.

    Highlights NEW event types, MISSING event types, and VOLUME SPIKES/DROPS.
    """
    _setup_logging(verbose)

    baseline_files = _collect_evtx_files([baseline])
    incident_files = _collect_evtx_files([incident])

    if not baseline_files:
        console.print(f"[red]No EVTX files in baseline: {baseline}[/red]")
        raise SystemExit(1)
    if not incident_files:
        console.print(f"[red]No EVTX files in incident: {incident}[/red]")
        raise SystemExit(1)

    console.print(
        f"[cyan]Baseline:[/cyan] {len(baseline_files)} files  "
        f"[cyan]Incident:[/cyan] {len(incident_files)} files"
    )

    # Build shared filter
    fc = empty_filter()
    pm = ProfileManager()
    profile_names = list(profile)
    if any(p.lower() == "all" for p in profile_names):
        profile_names = pm.list_names()
    if profile_names:
        fc = pm.build_filter(profile_names, base_filter=fc)

    # Parse both sets sequentially (each uses full thread pool)
    console.print("[dim]Parsing baseline...[/dim]")
    engine_b   = ProcessingEngine(max_workers=max_threads)
    base_events = engine_b.run(baseline_files, fc)
    console.print(f"[dim]  Baseline: {len(base_events):,} events[/dim]")

    console.print("[dim]Parsing incident...[/dim]")
    engine_i   = ProcessingEngine(max_workers=max_threads)
    inc_events  = engine_i.run(incident_files, fc)
    console.print(f"[dim]  Incident: {len(inc_events):,} events[/dim]")

    # Count per event ID
    def _count_eids(evts: list[dict]) -> dict[int, int]:
        d: dict[int, int] = {}
        for ev in evts:
            eid = ev.get("event_id", 0)
            d[eid] = d.get(eid, 0) + 1
        return d

    base_cnt = _count_eids(base_events)
    inc_cnt  = _count_eids(inc_events)
    base_set = set(base_cnt)
    inc_set  = set(inc_cnt)

    new_eids     = sorted(inc_set - base_set)
    missing_eids = sorted(base_set - inc_set)
    common       = sorted(base_set & inc_set)

    spikes = sorted(
        [(e, base_cnt[e], inc_cnt[e]) for e in common
         if inc_cnt[e] >= base_cnt[e] * spike_factor],
        key=lambda x: -(x[2] / max(x[1], 1))
    )
    drops = sorted(
        [(e, base_cnt[e], inc_cnt[e]) for e in common
         if base_cnt[e] >= inc_cnt[e] * spike_factor],
        key=lambda x: -(x[1] / max(x[2], 1))
    )

    # ── Display results ───────────────────────────────────────────────────
    console.print(f"\n[bold cyan]== DIFF REPORT ==[/bold cyan]")
    console.print(f"  Baseline: {len(base_events):,} events | {len(base_set)} unique Event IDs")
    console.print(f"  Incident: {len(inc_events):,} events | {len(inc_set)} unique Event IDs\n")

    if new_eids:
        t = Table(title=f"NEW Event IDs ({len(new_eids)}) -- in incident only",
                  header_style="bold red", border_style="red")
        t.add_column("EventID", style="bold")
        t.add_column("Count", justify="right")
        for eid in new_eids[:30]:
            t.add_row(str(eid), f"{inc_cnt[eid]:,}")
        console.print(t)

    if missing_eids:
        t = Table(
            title=f"MISSING Event IDs ({len(missing_eids)}) -- in baseline only "
                  f"(possible log clearing?)",
            header_style="bold yellow", border_style="yellow"
        )
        t.add_column("EventID", style="bold")
        t.add_column("Baseline Count", justify="right")
        for eid in missing_eids[:20]:
            t.add_row(str(eid), f"{base_cnt[eid]:,}")
        console.print(t)

    if spikes:
        t = Table(
            title=f"VOLUME SPIKES ({len(spikes)}) -- {spike_factor}x+ increase",
            header_style="bold magenta", border_style="magenta"
        )
        t.add_column("EventID", style="bold")
        t.add_column("Baseline",  justify="right")
        t.add_column("Incident",  justify="right")
        t.add_column("Ratio",     justify="right")
        for eid, b, i in spikes[:20]:
            t.add_row(str(eid), f"{b:,}", f"{i:,}", f"{i/max(b,1):.1f}x")
        console.print(t)

    if drops:
        t = Table(
            title=f"VOLUME DROPS ({len(drops)}) -- {spike_factor}x+ decrease",
            header_style="bold blue", border_style="blue"
        )
        t.add_column("EventID", style="bold")
        t.add_column("Baseline", justify="right")
        t.add_column("Incident", justify="right")
        for eid, b, i in drops[:10]:
            t.add_row(str(eid), f"{b:,}", f"{i:,}")
        console.print(t)

    # Diff events = new + spiking event IDs from incident
    spike_eids   = {eid for eid, _, _ in spikes}
    diff_events  = [
        ev for ev in inc_events
        if ev.get("event_id", 0) in (set(new_eids) | spike_eids)
    ]
    diff_events.sort(key=lambda e: e.get("timestamp", ""))
    console.print(
        f"\n[green]{len(diff_events):,} diff events "
        f"(new + spiking EIDs from incident)[/green]"
    )

    if output:
        count = export(diff_events, output, fmt)
        console.print(f"[green]Exported {count:,} events -> {output}[/green]")


# ── profiles command group ────────────────────────────────────────────────────

@cli.group("profiles")
def profiles_cmd():
    """Manage DFIR profiles."""
    pass


@profiles_cmd.command("list")
@click.option("--tag",    default=None, help="Filter by tag.")
@click.option("--search", default=None, help="Search by name substring.")
def profiles_list(tag, search):
    """List all available profiles."""
    pm  = ProfileManager()
    all_profiles = pm.list_profiles()
    if tag:
        all_profiles = [p for p in all_profiles
                        if tag.lower() in [t.lower() for t in p.get("tags", [])]]
    if search:
        all_profiles = [p for p in all_profiles
                        if search.lower() in p["name"].lower()]
    t = Table(title=f"DFIR Profiles ({len(all_profiles)})",
              header_style="bold cyan", border_style="cyan")
    t.add_column("#", width=4, justify="right", style="dim")
    t.add_column("Name", style="bold")
    t.add_column("IDs",  width=5, justify="right")
    t.add_column("Sources", width=25)
    t.add_column("Tags")
    t.add_column("Type", width=8)
    for i, p in enumerate(all_profiles, 1):
        ptype = "[yellow]custom[/yellow]" if p.get("_user_defined") else "[dim]built-in[/dim]"
        t.add_row(str(i), p["name"], str(len(p.get("event_ids", []))),
                  ", ".join(p.get("sources", [])[:2]),
                  ", ".join(p.get("tags", [])[:3]), ptype)
    console.print(t)


@profiles_cmd.command("show")
@click.argument("name")
def profiles_show(name):
    """Show details of a specific profile."""
    pm      = ProfileManager()
    profile = pm.get(name)
    if profile is None:
        matches = pm.get_by_partial_name(name)
        profile = matches[0] if matches else None
    if not profile:
        console.print(f"[red]Profile '{name}' not found.[/red]")
        raise SystemExit(1)
    console.print(f"\n[bold cyan]{profile['name']}[/bold cyan]")
    console.print(f"[dim]{profile.get('description', '')}[/dim]\n")
    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column(style="dim", width=18)
    t.add_column()
    t.add_row("Version",     profile.get("version", ""))
    t.add_row("Author",      profile.get("author", ""))
    t.add_row("Tags",        ", ".join(profile.get("tags", [])))
    t.add_row("Sources",     ", ".join(profile.get("sources", [])))
    t.add_row("Target Logs", ", ".join(profile.get("target_logs", [])))
    ids = profile.get("event_ids", [])
    t.add_row("Event IDs", f"[cyan]{', '.join(map(str, sorted(ids)))}[/cyan]")
    t.add_row("Total IDs",   str(len(ids)))
    if profile.get("keywords"):
        t.add_row("Keywords", ", ".join(profile["keywords"]))
    console.print(t)


@profiles_cmd.command("create")
@click.option("--name",        prompt="Profile name")
@click.option("--description", prompt="Description", default="")
@click.option("--event-ids",   prompt="Event IDs (comma-separated)")
@click.option("--sources",     prompt="Sources (comma-separated)", default="")
@click.option("--tags",        default="custom")
def profiles_create(name, description, event_ids, sources, tags):
    """Create a new custom profile."""
    pm   = ProfileManager()
    ids  = [int(x.strip()) for x in event_ids.split(",") if x.strip().isdigit()]
    srcs = [s.strip() for s in sources.split(",") if s.strip()]
    tlst = [t.strip() for t in tags.split(",") if t.strip()]
    p    = pm.create({"name": name, "description": description,
                      "event_ids": ids, "sources": srcs, "tags": tlst})
    console.print(f"[green]Created profile: {p['name']}[/green]")


@profiles_cmd.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="Delete this profile?")
def profiles_delete(name):
    """Delete a custom profile."""
    pm = ProfileManager()
    if pm.delete(name):
        console.print(f"[green]Deleted: {name}[/green]")
    else:
        console.print(f"[red]Cannot delete '{name}' (not found or built-in).[/red]")


@profiles_cmd.command("export")
@click.argument("name")
@click.argument("dest")
def profiles_export_cmd(name, dest):
    """Export a profile to a JSON file."""
    ProfileManager().export_profile(name, dest)
    console.print(f"[green]Exported '{name}' -> {dest}[/green]")


@profiles_cmd.command("import")
@click.argument("src")
@click.option("--overwrite", is_flag=True, default=False)
def profiles_import_cmd(src, overwrite):
    """Import a profile from a JSON file."""
    p = ProfileManager().import_profile(src, overwrite=overwrite)
    console.print(f"[green]Imported: {p['name']}[/green]")


@profiles_cmd.command("export-all")
@click.argument("dest_dir")
def profiles_export_all(dest_dir):
    """Export all profiles to a directory."""
    count = ProfileManager().export_all(dest_dir)
    console.print(f"[green]Exported {count} profiles -> {dest_dir}[/green]")


# ── benchmark command ─────────────────────────────────────────────────────────

@cli.command("benchmark")
@click.argument("paths", nargs=-1, required=True, metavar="FILE_OR_DIR...")
@click.option("--threads", multiple=True, type=int,
              help="Thread counts to test (repeat flag for multiple).")
def benchmark(paths, threads):
    """Benchmark parsing speed."""
    _setup_logging(False)
    files = _collect_evtx_files(list(paths))
    if not files:
        console.print("[red]No EVTX files found.[/red]")
        raise SystemExit(1)

    total_mb = sum(os.path.getsize(f) for f in files) / 1024 / 1024
    console.print(f"[cyan]Benchmark: {len(files)} files, {total_mb:.1f} MB[/cyan]")
    console.print(f"[dim]Backend: {get_backend()}[/dim]\n")

    cpu_count     = os.cpu_count() or 2
    thread_counts = list(threads) if threads else [1, max(1, cpu_count//2), max(1, cpu_count-1)]
    fc            = empty_filter()

    t = Table(title="Benchmark Results", header_style="bold cyan", border_style="cyan")
    t.add_column("Threads",  justify="right")
    t.add_column("Time (s)", justify="right")
    t.add_column("Records",  justify="right")
    t.add_column("Rec/sec",  justify="right")
    t.add_column("MB/sec",   justify="right")

    for n in thread_counts:
        console.print(f"[dim]Testing {n} thread(s)...[/dim]")
        engine  = ProcessingEngine(max_workers=n)
        t0      = time.monotonic()
        engine.run(files, fc)
        elapsed = time.monotonic() - t0
        records = engine.state.total_records_processed
        rps     = records / elapsed if elapsed > 0 else 0
        mbps    = total_mb / elapsed if elapsed > 0 else 0
        t.add_row(str(n), f"{elapsed:.2f}", f"{records:,}", f"{rps:,.0f}", f"{mbps:.1f}")
    console.print(t)


# ── interactive command ───────────────────────────────────────────────────────

@cli.command("interactive")
@click.argument("paths", nargs=-1, metavar="FILE_OR_DIR...")
def interactive(paths):
    """Interactive wizard: select profiles and filters, then parse."""
    pm        = ProfileManager()
    all_names = pm.list_names()

    console.print("[bold cyan]EventHawk v1.3 -- Interactive Mode[/bold cyan]\n")

    if not paths:
        path_input = click.prompt("Path to EVTX file(s) or directory")
        paths      = [path_input]

    files = _collect_evtx_files(list(paths))
    if not files:
        console.print("[red]No EVTX files found.[/red]")
        raise SystemExit(1)
    console.print(f"[green]Found {len(files)} EVTX file(s)[/green]\n")

    console.print("[bold]Available profiles:[/bold]")
    for i, name in enumerate(all_names, 1):
        console.print(f"  {i:2}. {name}")

    profile_input = click.prompt(
        "\nSelect profiles (numbers, 'all', or blank for none)", default=""
    )
    selected: list[str] = []
    if profile_input.strip().lower() == "all":
        selected = all_names
    elif profile_input.strip():
        for part in profile_input.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(all_names):
                    selected.append(all_names[idx])

    fc = empty_filter()
    if selected:
        fc = pm.build_filter(selected, fc)
        console.print(f"[magenta]Profiles: {', '.join(selected)}[/magenta]")

    do_attack    = click.confirm("Enable ATT&CK tagging?",   default=True)
    do_ioc       = click.confirm("Extract IOCs?",             default=False)
    do_correlate = click.confirm("Run correlation engine?",   default=False)

    output = click.prompt("Output file (blank for console)", default="")
    fmt    = None
    if output:
        ext = Path(output).suffix.lstrip(".").lower()
        if ext not in EXPORT_FORMATS:
            fmt = click.prompt("Format",
                               type=click.Choice(list(EXPORT_FORMATS.keys())),
                               default="html")

    cpu_count   = os.cpu_count() or 2
    max_threads = click.prompt("Max threads", default=max(1, cpu_count-1), type=int)

    console.print("\n[dim]Starting analysis...[/dim]\n")
    engine = ProcessingEngine(max_workers=max_threads)
    tui    = EVTXParserTUI(console=console)
    tui.set_context(profiles=selected, filters="")
    engine._on_progress = tui.update_state
    tui.start()
    try:
        all_events = engine.run(files, fc)
    finally:
        state = engine.state.snapshot()
        tui.stop()
        time.sleep(0.4)
        tui.print_summary(all_events, state)

    all_events.sort(key=lambda e: e.get("timestamp", ""))
    attack_summary, iocs_result, chains = _run_analysis(
        all_events, do_attack, do_ioc, do_correlate
    )

    if output:
        count = export(all_events, output, fmt,
                       attack_summary=attack_summary,
                       iocs=iocs_result, chains=chains)
        console.print(f"[green]Exported {count:,} events -> {output}[/green]")


# ── gui command ───────────────────────────────────────────────────────────────

@cli.command("gui")
@click.argument("paths", nargs=-1, required=False, metavar="[FILE_OR_DIR...]")
def gui_cmd(paths):
    """Launch the graphical interface (PySide6 dark-theme DFIR GUI)."""
    try:
        from evtx_tool.gui.app import launch
    except ImportError:
        console.print(
            "[red]PySide6 is not installed.[/red]\n"
            "Install it with:  py -3 -m pip install PySide6"
        )
        raise SystemExit(1)
    launch(list(paths))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_events_table(events: list[dict]) -> None:
    t = Table(show_header=True, header_style="bold cyan", border_style="dim")
    t.add_column("Timestamp", width=20)
    t.add_column("EventID",   width=8,  justify="right")
    t.add_column("Level",     width=12)
    t.add_column("Channel",   width=22)
    t.add_column("Computer",  width=15)
    t.add_column("ATT&CK",    width=16)
    t.add_column("Source",    width=22)
    color_map = {
        "Critical": "red", "Error": "red", "Warning": "yellow",
        "Information": "green", "Verbose": "dim",
    }
    for ev in events[:200]:
        lvl  = ev.get("level_name", "")
        ts   = ev.get("timestamp", "").replace("T", " ").replace("Z", "")[:19]
        tags = ev.get("attack_tags") or []
        atk  = tags[0]["tid"] if tags else ""
        t.add_row(
            ts, str(ev.get("event_id", "")),
            Text(lvl, style=color_map.get(lvl, "white")),
            ev.get("channel", ""),
            ev.get("computer", ""),
            atk,
            os.path.basename(ev.get("source_file", "")),
        )
    console.print(t)
    if len(events) > 200:
        console.print(
            f"[dim]... and {len(events)-200:,} more. Use --output to save all.[/dim]"
        )
