"""
Rich-based Terminal UI for EventHawk.

Layout:
  ┌─ Header ────────────────────────────────────────────────┐
  │ EventHawk v1.2                            [Ctrl+C stop] │
  ├─ Resource Monitor ──────┬─ Progress ───────────────────┤
  │ CPU ████░░░ 72%         │ Files: [████░░░] 67/100       │
  │ RAM ███░░░░ 45%         │ Events matched: 45,231        │
  │ Threads: 7 / 11         │ Records/sec: 91,000           │
  ├─ Active Profiles ───────┴─────────────────────────────── │
  │ Logon/Logoff, RDP Activity, Privilege Escalation         │
  ├─ Recent Events ─────────────────────────────────────────┤
  │ 2026-02-17 02:13  4624  Info   Security   MSI           │
  │ 2026-02-17 02:12  4625  WARN   Security   MSI           │
  ├─ Warnings / Errors ─────────────────────────────────────┤
  └─────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable

from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

LEVEL_COLORS = {
    "Critical":    "bold red",
    "Error":       "red",
    "Warning":     "yellow",
    "Information": "green",
    "Verbose":     "dim white",
    "LogAlways":   "white",
}

SUSPICIOUS_IDS = {
    4625, 4648, 4697, 4698, 4702, 4720, 4740, 4776, 4768, 4769,
    7045, 1102, 4719, 4735, 4728, 4732, 4756, 4771, 4672,
}


class EVTXParserTUI:
    """
    Manages the Rich Live display. Updated externally via update_state().
    Run .start() in a background thread, or use as context manager.
    """

    REFRESH_RATE = 4  # renders per second

    def __init__(self, console: Console | None = None, title: str = "EventHawk v1.2"):
        self._console = console or Console()
        self._title = title
        self._live: Live | None = None
        self._state: dict = {}
        self._lock = threading.Lock()
        self._active_profiles: list[str] = []
        self._active_filters: str = ""
        self._stop_event = threading.Event()

        # Progress bar widget (updated externally)
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self._console,
        )
        self._file_task = self._progress.add_task("Files", total=1)

    # ── Public API ─────────────────────────────────────────────────────────────

    def set_context(self, profiles: list[str], filters: str) -> None:
        self._active_profiles = profiles
        self._active_filters = filters

    def update_state(self, state: dict) -> None:
        with self._lock:
            self._state = state
            total = max(state.get("total_files", 1), 1)
            done  = state.get("done_files", 0)
            self._progress.update(self._file_task, total=total, completed=done,
                                  description="Processing")

    def start(self) -> None:
        """Start the Live display in a background daemon thread."""
        t = threading.Thread(target=self._run_loop, daemon=True, name="TUI")
        t.start()

    def stop(self) -> None:
        self._stop_event.set()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
        time.sleep(0.3)

    # ── Rendering loop ─────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        with Live(
            self._build_layout(),
            console=self._console,
            refresh_per_second=self.REFRESH_RATE,
            screen=False,
        ) as live:
            self._live = live
            while not self._stop_event.is_set():
                try:
                    live.update(self._build_layout())
                except Exception:
                    pass
                time.sleep(1 / self.REFRESH_RATE)

    # ── Layout builders ────────────────────────────────────────────────────────

    def _build_layout(self) -> Panel:
        with self._lock:
            state = dict(self._state)

        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)

        # Row 1: Resource Monitor | Progress
        grid.add_row(
            self._make_resource_panel(state),
            self._make_progress_panel(state),
        )

        # Row 2: Profiles/Filters (full width)
        grid.add_row(
            self._make_context_panel(),
            Text(""),
        )

        # Row 3: Recent Events (full width via nested grid)
        events_panel = self._make_events_panel(state)
        warnings_panel = self._make_warnings_panel(state)

        outer = Table.grid(expand=True)
        outer.add_column()
        outer.add_row(grid)
        outer.add_row(events_panel)
        outer.add_row(warnings_panel)

        phase = state.get("phase", "idle")
        phase_colors = {
            "running": "green",
            "throttled": "yellow",
            "done": "bold green",
            "error": "bold red",
            "idle": "dim white",
        }
        border_color = phase_colors.get(phase, "blue")

        return Panel(
            outer,
            title=f"[bold cyan]{self._title}[/bold cyan]",
            subtitle="[dim]Ctrl+C to stop[/dim]",
            border_style=border_color,
        )

    def _make_resource_panel(self, state: dict) -> Panel:
        rs = state.get("resource_stats")
        cpu = rs.sys_cpu_pct if rs else 0.0
        ram = rs.sys_ram_pct if rs else 0.0
        ram_avail = rs.ram_available_mb if rs else 0.0
        proc_ram = rs.proc_ram_mb if rs else 0.0
        throttle = rs.throttle_active if rs else False
        mem_pressure = rs.memory_pressure if rs else False

        cpu_limit = rs.cpu_limit if rs else 85.0
        ram_limit = rs.ram_limit if rs else 80.0

        cpu_bar = self._make_bar(cpu, 100, width=20,
                                  color="red" if throttle else ("yellow" if cpu > cpu_limit * 0.9 else "green"))
        ram_bar = self._make_bar(ram, 100, width=20,
                                  color="red" if mem_pressure else ("yellow" if ram > ram_limit * 0.9 else "blue"))

        workers = state.get("active_workers", 0)
        max_workers = state.get("max_workers", 0)
        throttle_text = " [yellow]THROTTLED[/yellow]" if throttle else ""
        mem_text = " [red]MEM PRESSURE[/red]" if mem_pressure else ""

        t = Table.grid(padding=(0, 1))
        t.add_column(style="dim", width=8)
        t.add_column()
        t.add_row("CPU", f"{cpu_bar} {cpu:5.1f}%{throttle_text}")
        t.add_row("RAM", f"{ram_bar} {ram:5.1f}%{mem_text}")
        t.add_row("Avail", f"[cyan]{ram_avail:,.0f} MB[/cyan]")
        t.add_row("Process", f"[dim]{proc_ram:,.0f} MB RSS[/dim]")
        t.add_row("Workers", f"[bold]{workers}[/bold] / {max_workers}")

        return Panel(t, title="[bold]Resource Monitor[/bold]", border_style="cyan", padding=(0, 1))

    def _make_progress_panel(self, state: dict) -> Panel:
        total_f = state.get("total_files", 0)
        done_f  = state.get("done_files", 0)
        failed  = state.get("failed_files", 0)
        matched = state.get("total_events_matched", 0)
        total_r = state.get("total_records_processed", 0)
        eps     = state.get("events_per_sec", 0.0)
        elapsed = state.get("elapsed_sec", 0.0)
        phase   = state.get("phase", "idle")

        phase_text = {
            "running":   "[green][+] Running[/green]",
            "throttled": "[yellow][!] Throttled[/yellow]",
            "done":      "[bold green][OK] Complete[/bold green]",
            "error":     "[bold red][X] Error[/bold red]",
            "idle":      "[dim][ ] Idle[/dim]",
        }.get(phase, phase)

        elapsed_str = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"

        bar = self._make_bar(done_f, max(total_f, 1), width=25, color="green")

        t = Table.grid(padding=(0, 1))
        t.add_column(style="dim", width=10)
        t.add_column()
        t.add_row("Status", phase_text)
        t.add_row("Files", f"{bar} {done_f}/{total_f}" + (f" [red]({failed} failed)[/red]" if failed else ""))
        t.add_row("Matched", f"[bold cyan]{matched:,}[/bold cyan] events")
        t.add_row("Scanned", f"[dim]{total_r:,}[/dim] records")
        t.add_row("Rate", f"[yellow]{eps:,.0f}[/yellow] events/sec")
        t.add_row("Elapsed", f"[dim]{elapsed_str}[/dim]")

        return Panel(t, title="[bold]Progress[/bold]", border_style="green", padding=(0, 1))

    def _make_context_panel(self) -> Panel:
        profiles_str = (
            ", ".join(f"[bold magenta]{p}[/bold magenta]" for p in self._active_profiles)
            if self._active_profiles else "[dim]None — all events[/dim]"
        )
        filters_str = self._active_filters or "[dim]None[/dim]"

        t = Table.grid(padding=(0, 1))
        t.add_column(style="dim", width=12)
        t.add_column()
        t.add_row("Profiles", profiles_str)
        t.add_row("Filters", filters_str)

        return Panel(t, title="[bold]Active Configuration[/bold]", border_style="magenta", padding=(0, 0))

    def _make_events_panel(self, state: dict) -> Panel:
        recent = state.get("recent_events", [])[-15:]

        table = Table(
            show_header=True,
            header_style="bold cyan",
            show_edge=False,
            pad_edge=False,
            expand=True,
        )
        table.add_column("Timestamp", style="dim", width=22, no_wrap=True)
        table.add_column("EventID", width=8, justify="right")
        table.add_column("Level", width=12)
        table.add_column("Channel", width=20, no_wrap=True)
        table.add_column("Computer", width=18, no_wrap=True)
        table.add_column("Source File", width=25, no_wrap=True)
        table.add_column("Key Data", ratio=1)

        for ev in reversed(recent):
            eid = ev.get("event_id", 0)
            lvl = ev.get("level_name", "Information")
            lvl_color = LEVEL_COLORS.get(lvl, "white")
            is_suspicious = eid in SUSPICIOUS_IDS

            ts = ev.get("timestamp", "")
            if "T" in ts:
                ts = ts.replace("T", " ").replace("Z", "")[:19]

            # Extract most useful EventData field
            ed = ev.get("event_data", {}) or {}
            key_data = self._pick_key_data(eid, ed)

            eid_text = Text(str(eid), style="bold yellow" if is_suspicious else "bold cyan")
            if is_suspicious:
                eid_text.append(" [W]", style="bold red")

            table.add_row(
                ts,
                eid_text,
                Text(lvl, style=lvl_color),
                ev.get("channel", ""),
                ev.get("computer", ""),
                os.path.basename(ev.get("source_file", "")),
                Text(key_data, style="dim"),
            )

        count = len(recent)
        matched = state.get("total_events_matched", 0)
        title = f"[bold]Recent Events[/bold] [dim](showing {count} of {matched:,} matched)[/dim]"
        return Panel(table, title=title, border_style="blue", padding=(0, 0))

    def _make_warnings_panel(self, state: dict) -> Panel:
        warnings = state.get("warnings", [])
        errors   = state.get("errors", [])

        lines: list[Text] = []
        for w in warnings[-5:]:
            lines.append(Text(f"[!] {w}", style="yellow"))
        for e in errors[-5:]:
            lines.append(Text(f"[X] {e}", style="red"))

        if not lines:
            content = Text("No warnings or errors", style="dim")
        else:
            # BUG 28 fix: Rich.Text has no .join() method; build by appending
            content = Text()
            for i, line in enumerate(lines):
                if i > 0:
                    content.append("\n")
                content.append_text(line)

        return Panel(content, title="[bold]Warnings / Errors[/bold]", border_style="yellow",
                     padding=(0, 1))

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _make_bar(value: float, maximum: float, width: int = 20, color: str = "green") -> str:
        if maximum == 0:
            filled = 0
        else:
            filled = int(round((value / maximum) * width))
        filled = max(0, min(filled, width))
        empty = width - filled
        bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"
        return bar

    @staticmethod
    def _pick_key_data(event_id: int, ed: dict) -> str:
        """Pick the most forensically relevant EventData field for display."""
        priority_fields = [
            "TargetUserName", "SubjectUserName", "UserName",
            "NewProcessName", "ImageFileName", "ProcessName",
            "CommandLine", "TargetServerName", "ShareName",
            "ServiceName", "ServiceFileName", "TaskName",
            "ObjectName", "DeviceId", "RemoteAddress",
            "IpAddress", "CalledProcessName",
        ]
        for field in priority_fields:
            val = ed.get(field)
            if val and str(val).strip() not in ("-", ""):
                return f"{field}: {str(val)[:60]}"
        # Fallback: first non-empty field
        for k, v in ed.items():
            if v and str(v).strip() not in ("-", ""):
                return f"{k}: {str(v)[:60]}"
        return ""

    # ── Summary display (after completion) ────────────────────────────────────

    def print_summary(self, events: list[dict], state: dict) -> None:
        """Print a final summary table to the console."""
        self._console.print()
        self._console.rule("[bold cyan]Analysis Complete[/bold cyan]")

        from collections import Counter
        eid_counts = Counter(ev.get("event_id", 0) for ev in events)
        lvl_counts = Counter(ev.get("level_name", "") for ev in events)
        src_counts = Counter(os.path.basename(ev.get("source_file", "")) for ev in events)

        # Summary stats
        t = Table(title="Summary", show_header=True, header_style="bold cyan",
                  border_style="cyan", expand=False)
        t.add_column("Metric", style="dim")
        t.add_column("Value", justify="right")

        elapsed = state.get("elapsed_sec", 0)
        t.add_row("Files processed", f"{state.get('done_files', 0):,}")
        t.add_row("Total records scanned", f"{state.get('total_records_processed', 0):,}")
        t.add_row("Events matched", f"[bold cyan]{len(events):,}[/bold cyan]")
        t.add_row("Failed files", f"[red]{state.get('failed_files', 0)}[/red]")
        t.add_row("Elapsed time", f"{elapsed:.1f}s")
        t.add_row("Events/sec", f"{len(events)/elapsed:.0f}" if elapsed > 0 else "N/A")
        self._console.print(t)

        # Top event IDs
        if eid_counts:
            t2 = Table(title="Top 10 Event IDs", show_header=True, header_style="bold green",
                       border_style="green", expand=False)
            t2.add_column("Event ID", style="bold cyan")
            t2.add_column("Count", justify="right")
            t2.add_column("Suspicious", justify="center")
            for eid, cnt in eid_counts.most_common(10):
                susp = "[W] YES" if eid in SUSPICIOUS_IDS else ""
                t2.add_row(str(eid), f"{cnt:,}", Text(susp, style="bold red" if susp else "dim"))
            self._console.print(t2)

        # Level distribution
        if lvl_counts:
            t3 = Table(title="Level Distribution", show_header=True, header_style="bold yellow",
                       border_style="yellow", expand=False)
            t3.add_column("Level")
            t3.add_column("Count", justify="right")
            for lvl, cnt in sorted(lvl_counts.items(), key=lambda x: -x[1]):
                color = LEVEL_COLORS.get(lvl, "white")
                t3.add_row(Text(lvl, style=color), f"{cnt:,}")
            self._console.print(t3)
