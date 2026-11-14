"""System Activity tool: the dialog and its Juggernaut fetch worker.

The periods and moments come from evtx_tool.analysis.system_activity.build();
this module only shows them.  Times are UTC like the other session tools, at
the analyst's chosen precision; durations are exact (host_power.fmt_secs).
"""
from __future__ import annotations

import json as _json
import logging
import os
from datetime import timedelta

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QFileDialog, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout)

from evtx_tool.analysis.host_power import fmt_secs
from evtx_tool.gui.theme import COLORS, rebuild_on_theme, tc
from evtx_tool.analysis.system_activity import ACTIVITY_SQL

logger = logging.getLogger(__name__)

TIMELINE_HEADERS = ["Computer", "Layer", "Activity", "Start (UTC)", "End (UTC)", "Duration",
                    "Started by", "Ended by", "Notes"]
MOMENT_HEADERS = ["Computer", "Time (UTC)", "What happened", "Details", "Evidence"]

_COLOURS = {"On": "#e3f4e1", "Sleep": "#dde7f7", "Hibernate": "#e6dff5", "Sleep or hibernate": "#dde7f7",
            "Modern Standby": "#e4eef2", "Shut down": "#e8e6e3", "Off": "#e8e6e3",
            "Off (unexpected shutdown)": "#f8dcd6", "Locked": "#fbefd2", "Screen saver": "#fbefd2"}

COVERAGE = ("Screen on/off comes from Kernel-Power 566 (Windows 10 2004 and later, Windows 11); its session "
            "types (0 screen on, 1 screen off, 3 sleep) are inferred from the logs, not documented by Microsoft. "
            "Lock and screen saver need the Security policy \"Audit Other Logon/Logoff Events\", off by default. "
            "A time the events do not prove reads Unavailable.")


# Periods shorter than this are hidden by default (a checkbox shows how many):
# Modern Standby and power transitions leave hundreds of real but
# split-second rows that buried the periods an analyst reads the timeline for.
SHORT_PERIOD_SECS = 1.0

# Legend: (label, colour key in _COLOURS)
_LEGEND = (("On", "On"), ("Sleep / hibernate", "Sleep"), ("Hibernate", "Hibernate"),
           ("Modern Standby", "Modern Standby"), ("Shut down / off", "Shut down"),
           ("Unexpected shutdown", "Off (unexpected shutdown)"), ("Locked", "Locked"))


def fmt_total(td) -> str:
    """A summary total in reading units: 479 h 06 m, 3 m 12 s, 0.4 s."""
    secs = td.total_seconds()
    if secs < 60:
        return f"{secs:.1f} s" if secs < 10 else f"{int(secs)} s"
    mins = int(secs // 60)
    if mins < 60:
        return f"{mins} m {int(secs % 60):02d} s"
    h, m = divmod(mins, 60)
    return f"{h} h {m:02d} m"


def fmt_duration(td, digits: int) -> str:
    """A period's duration at the display precision, truncated like the
    timestamps (the exact value is the cell's tooltip and the CSV's)."""
    if td is None:
        return "Unavailable"
    if digits >= 6:
        return fmt_secs(td)
    us = int(round(td.total_seconds() * 1_000_000))
    step = 10 ** (6 - digits)
    return fmt_secs(timedelta(microseconds=us - us % step))


def fmt_time(d, digits: int) -> str:
    if d is None:
        return "Unavailable"
    s = d.strftime("%Y-%m-%d %H:%M:%S")
    return s + (f".{d.microsecond:06d}"[:digits + 1] if digits else "")


class _SortItem(QTableWidgetItem):
    """Sorts by its UserRole+1 key (time or seconds); text otherwise."""

    def __lt__(self, other):
        a, b = self.data(Qt.ItemDataRole.UserRole + 1), other.data(Qt.ItemDataRole.UserRole + 1)
        if a is not None and b is not None:
            try:
                return a < b
            except TypeError:
                pass
        # Not super().__lt__: from a Python override it dispatches back here
        # and recursed until the stack overflowed (access violation on sort).
        return self.text() < other.text()


class SystemActivityDialog(QDialog):
    """Two tabs - Timeline (periods) and Moments - filtered by computer, layer and text."""

    def __init__(self, result: dict, parent=None, around=None, digits: int = 0, events=None):
        super().__init__(parent)
        self._res = result
        self._events = events            # the raw events the analysis read (HTML report)
        self._around = around            # callable(ev, timedelta) or None
        self._digits = digits
        self._shown_rows: list = []
        self._shown_points: list = []
        self.setWindowTitle("System Activity")
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowMinMaxButtonsHint
                            | Qt.WindowType.WindowCloseButtonHint)
        self.resize(1450, 680)
        self._build_ui()
        self._refresh()

    # ── UI ──────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        self._lbl_summary = QLabel()
        self._lbl_summary.setWordWrap(True)
        self._lbl_summary.setTextFormat(Qt.TextFormat.RichText)
        root.addWidget(self._lbl_summary)
        cov = QLabel(COVERAGE)
        cov.setWordWrap(True)
        cov.setStyleSheet(f"color:{COLORS['text_dim']}; font-size:8pt;")
        root.addWidget(cov)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Computer:"))
        self._cmb_host = QComboBox()
        self._cmb_host.addItem("All computers", None)
        for h in self._res.get("hosts", []):
            self._cmb_host.addItem(h or "(no computer name)", h)
        if len(self._res.get("hosts", [])) == 1:
            self._cmb_host.setCurrentIndex(1)
        self._cmb_host.currentIndexChanged.connect(self._refresh)
        bar.addWidget(self._cmb_host)
        self._chk = {}
        for name, tip in (("Power", "On, sleep, hibernate, Modern Standby, shut down"),
                          ("Screen", "Screen on / off (Kernel-Power 566)"),
                          ("Lock", "Locked / screen saver (Security 4800-4803)")):
            c = QCheckBox(name)
            c.setChecked(True)
            c.setToolTip(tip)
            c.toggled.connect(self._refresh)
            bar.addWidget(c)
            self._chk[name] = c
        self._chk_short = QCheckBox("Hide periods under 1 s")
        self._chk_short.setChecked(True)
        self._chk_short.setToolTip(
            "Split-second periods (Modern Standby and power transitions) are real "
            "but bury the periods that matter.  The summary totals always count "
            "every period; Export writes the rows shown.")
        self._chk_short.toggled.connect(self._refresh)
        bar.addWidget(self._chk_short)
        bar.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by activity, evidence or notes…")
        self._search.textChanged.connect(self._refresh)
        bar.addWidget(self._search, 1)
        root.addLayout(bar)

        legend = QHBoxLayout()
        legend.setSpacing(6)
        for label, key in _LEGEND:
            chip = QLabel(label)
            chip.setStyleSheet(f"background:{tc(_COLOURS[key])}; color:{COLORS['text']}; "
                               "border-radius:3px; padding:1px 7px; font-size:8pt;")
            legend.addWidget(chip)
        legend.addStretch()
        root.addLayout(legend)

        self._tabs = QTabWidget()
        one_host = len(self._res.get("hosts", [])) <= 1
        self._tbl = self._table(TIMELINE_HEADERS, [80 if one_host else 150, 60, 190, 150, 150, 100, 230, 230, 300])
        self._tbl_pts = self._table(MOMENT_HEADERS, [80 if one_host else 150, 150, 230, 520, 200])
        # The last column (Notes / Evidence) takes the spare width, and the
        # selected row is shown in full below: long notes were cut off and
        # could only be read by dragging the column wider.
        for t in (self._tbl, self._tbl_pts):
            t.horizontalHeader().setStretchLastSection(True)
            t.itemSelectionChanged.connect(lambda tt=t: self._show_details(tt))
        self._tabs.addTab(self._tbl, "Timeline")
        self._tabs.addTab(self._tbl_pts, "Moments")
        self._tabs.currentChanged.connect(lambda _i: self._show_details(self._tabs.currentWidget()))
        root.addWidget(self._tabs, 1)

        self._lbl_details = QLabel()
        self._lbl_details.setObjectName("periodDetails")
        self._lbl_details.setWordWrap(True)
        self._lbl_details.setTextFormat(Qt.TextFormat.RichText)
        self._lbl_details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._lbl_details.setMinimumHeight(52)
        self._lbl_details.setStyleSheet(
            f"QLabel#periodDetails {{ background:{COLORS['bg_panel']}; color:{COLORS['text']};"
            f" border-radius:4px; padding:6px 10px; }}")
        root.addWidget(self._lbl_details)

        btns = QHBoxLayout()
        b = QPushButton("Export HTML Report…")
        b.setToolTip("One self-contained file: overview, calendar, day-by-day timeline, every period, "
                     "moment and raw event with all fields, searchable. Opens offline in any browser.")
        b.clicked.connect(self._export_html)
        btns.addWidget(b)
        self._btn_html = b
        b = QPushButton("Export Timeline CSV")
        b.clicked.connect(lambda: self._export(timeline=True))
        btns.addWidget(b)
        b = QPushButton("Export Moments CSV")
        b.clicked.connect(lambda: self._export(timeline=False))
        btns.addWidget(b)
        btns.addStretch()
        b = QPushButton("Close")
        b.clicked.connect(self.close)
        btns.addWidget(b)
        root.addLayout(btns)

    def _table(self, headers, widths):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSortingEnabled(True)
        t.verticalHeader().setVisible(False)
        t.verticalHeader().setDefaultSectionSize(22)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for i, w in enumerate(widths):
            t.setColumnWidth(i, w)
        t.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        t.customContextMenuRequested.connect(lambda pos, tt=t: self._menu(tt, pos))
        return t

    # ── content ─────────────────────────────────────────────────────────────
    def _filters(self):
        host = self._cmb_host.currentData()
        layers = {n for n, c in self._chk.items() if c.isChecked()}
        text = self._search.text().strip().lower()
        return host, layers, text

    def row_cells(self, r):
        return [r["host"], r["layer"], r["state"], fmt_time(r["start"], self._digits),
                fmt_time(r["end"], self._digits), fmt_secs(r["duration"]) if r["duration"] is not None
                else "Unavailable", r["started_by"], r["ended_by"], r["notes"]]

    def row_cells_display(self, r):
        """As row_cells, with the duration at the display precision."""
        cells = self.row_cells(r)
        cells[5] = fmt_duration(r["duration"], self._digits)
        return cells

    def point_cells(self, p):
        return [p["host"], fmt_time(p["time"], self._digits), p["what"], p["details"], p["evidence"]]

    def _refresh(self, *_):
        host, layers, text = self._filters()
        rows = [r for r in self._res.get("rows", []) if (host is None or r["host"] == host)
                and r["layer"] in layers]
        short = [r for r in rows if r["duration"] is not None
                 and r["duration"].total_seconds() < SHORT_PERIOD_SECS]
        self._chk_short.setText(f"Hide periods under 1 s ({len(short):,})")
        if self._chk_short.isChecked() and short:
            hide = {id(r) for r in short}
            rows = [r for r in rows if id(r) not in hide]
        pts = [p for p in self._res.get("points", []) if host is None or p["host"] == host]
        if text:
            rows = [r for r in rows if any(text in str(c).lower() for c in self.row_cells(r))]
            pts = [p for p in pts if any(text in str(c).lower() for c in self.point_cells(p))]
        self._fill(self._tbl, rows, self.row_cells_display, lambda r: (r["start"], r["end"], r["duration"]),
                   lambda r: _COLOURS.get(r["state"]))
        self._fill(self._tbl_pts, pts, self.point_cells, lambda p: (p["time"], None, None), lambda p: None)
        self._shown_rows, self._shown_points = rows, pts
        if hasattr(self, "_lbl_details"):
            self._show_details(self._tabs.currentWidget())
        self._tabs.setTabText(0, f"Timeline ({len(rows):,})")
        self._tabs.setTabText(1, f"Moments ({len(pts):,})")
        self._summary(host)

    def _fill(self, tbl, items, cells, keys, colour):
        tbl.setSortingEnabled(False)
        tbl.setRowCount(len(items))
        for i, it in enumerate(items):
            k_start, k_end, k_dur = keys(it)
            bg = colour(it)
            for c, txt in enumerate(cells(it)):
                cell = _SortItem(str(txt))
                cell.setData(Qt.ItemDataRole.UserRole, i)
                key = None
                if tbl is self._tbl:
                    key = {3: k_start, 4: k_end, 5: k_dur.total_seconds() if k_dur is not None else None}.get(c)
                elif c == 1:
                    key = k_start
                if key is not None:
                    cell.setData(Qt.ItemDataRole.UserRole + 1, key.isoformat() if hasattr(key, "isoformat") else key)
                if tbl is self._tbl and c == 5 and k_dur is not None:
                    cell.setToolTip(f"Exact: {fmt_secs(k_dur)}")
                if bg:
                    cell.setBackground(QColor(tc(bg)))
                tbl.setItem(i, c, cell)
        tbl.setSortingEnabled(True)

    @rebuild_on_theme
    def _summary(self, host):
        rows = [r for r in self._res.get("rows", []) if host is None or r["host"] == host]
        if not rows and not self._res.get("points"):
            self._lbl_summary.setText("<b>No power, screen or lock events found.</b>")
            return
        tot: dict = {}                       # (layer, label) -> total
        unknown = 0
        for r in rows:
            if r["duration"] is None:
                unknown += 1
                continue
            label = r["state"].split(" (session type")[0]
            key = (r["layer"], label)
            tot[key] = tot.get(key, timedelta(0)) + r["duration"]
        order = ["On", "Screen on", "Screen off", "Sleep", "Hibernate", "Sleep or hibernate", "Modern Standby",
                 "Locked", "Screen saver", "Shut down", "Off"]
        rank = {k: i for i, k in enumerate(order)}
        who = host if host is not None else f"{len(self._res.get('hosts', []))} computer(s)"
        lines, exact = [], []
        for layer in ("Power", "Screen", "Lock"):
            items = sorted(((lbl, v) for (ly, lbl), v in tot.items() if ly == layer),
                           key=lambda kv: (rank.get(kv[0], 99), kv[0]))
            if not items:
                continue
            lines.append(f"<b>{layer}</b>&nbsp; " + " &nbsp;·&nbsp; ".join(
                f"{lbl} <b>{fmt_total(v)}</b>" for lbl, v in items))
            exact += [f"{layer} / {lbl}: {fmt_secs(v)}" for lbl, v in items]
        txt = f"<b>{who}</b>" + ("<br>" + "<br>".join(lines) if lines else "")
        if unknown:
            txt += (f"<br><span style='color:{tc('#8a4800')};'>{unknown} period(s) with an unknown start or "
                    f"end are not in these totals</span>")
        if host is not None and not any(r["layer"] == "Screen" for r in rows):
            txt += "<br>No screen data (no Kernel-Power 566 in these logs)"
        self._lbl_summary.setToolTip("Exact totals:\n" + "\n".join(exact) if exact else "")
        self._lbl_summary.setText(txt)

    # ── selected row, in full ───────────────────────────────────────────────
    @staticmethod
    def _esc(v) -> str:
        return (str(v if v is not None else "").replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;"))

    def _show_details(self, tbl) -> None:
        """The selected period / moment with every field unclipped (wraps)."""
        rows = tbl.selectionModel().selectedRows() if tbl is not None and tbl.selectionModel() else []
        if not rows:
            self._lbl_details.setText(
                f"<span style='color:{COLORS['text_dim']}'>Select a row to see it in full here "
                "(notes, evidence, exact duration).</span>")
            return
        cell = tbl.item(rows[0].row(), 0)
        i = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        src = self._shown_rows if tbl is self._tbl else self._shown_points
        if i is None or not (0 <= i < len(src)):
            return
        it, e = src[i], self._esc
        dim = COLORS["text_dim"]
        if tbl is self._tbl:
            dur = fmt_secs(it["duration"]) if it["duration"] is not None else "Unavailable"
            html = (f"<b>{e(it['state'])}</b> &nbsp;<span style='color:{dim}'>{e(it['layer'])} · {e(it['host'])}"
                    f"</span><br>{e(fmt_time(it['start'], 6))} &nbsp;→&nbsp; {e(fmt_time(it['end'], 6))} UTC"
                    f" &nbsp;·&nbsp; <b>{e(dur)}</b><br>"
                    f"<span style='color:{dim}'>Started by</span> {e(it['started_by'])} &nbsp;·&nbsp; "
                    f"<span style='color:{dim}'>Ended by</span> {e(it['ended_by'])}")
            if it.get("notes"):
                html += f"<br><span style='color:{dim}'>Notes</span> {e(it['notes'])}"
        else:
            html = (f"<b>{e(it['what'])}</b> &nbsp;<span style='color:{dim}'>{e(it['host'])}</span>"
                    f"<br>{e(fmt_time(it['time'], 6))} UTC<br>{e(it['details'])}"
                    f"<br><span style='color:{dim}'>Evidence</span> {e(it['evidence'])}")
        self._lbl_details.setText(html)

    # ── context menu / Around ───────────────────────────────────────────────
    def _item_at(self, tbl, pos):
        idx = tbl.indexAt(pos)
        if not idx.isValid():
            return None
        cell = tbl.item(idx.row(), 0)
        i = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        src = self._shown_rows if tbl is self._tbl else self._shown_points
        return src[i] if i is not None and 0 <= i < len(src) else None

    def _menu(self, tbl, pos):
        it = self._item_at(tbl, pos)
        if it is None:
            return
        from PySide6.QtGui import QGuiApplication
        m = QMenu(self)
        cells = self.row_cells(it) if tbl is self._tbl else self.point_cells(it)
        a = m.addAction("Copy row")
        a.triggered.connect(lambda: QGuiApplication.clipboard().setText("\t".join(map(str, cells))))
        if self._around is not None:
            for what, ev, at in self.around_targets(it, timeline=tbl is self._tbl):
                m.addSeparator()
                for label, td in (("±5 minutes", timedelta(minutes=5)), ("±30 minutes", timedelta(minutes=30))):
                    act = m.addAction(f"Events around this {what} ({label})")
                    act.triggered.connect(lambda _=False, e=ev, d=td, a=at: self.go_around(e, d, a))
        m.exec(tbl.viewport().mapToGlobal(pos))

    @staticmethod
    def around_targets(it, timeline: bool):
        """(what, evidence event, time) for each "Events around" action.  The
        window is centred on the time shown - a sleep's start is its SleepTime,
        not the time of the wake record that carries it (Codex SA-1)."""
        cand = ([("start", it.get("start_ev"), it.get("start")), ("end", it.get("end_ev"), it.get("end"))]
                if timeline else [("moment", it.get("ev"), it.get("time"))])
        return [c for c in cand if c[1] is not None and c[2] is not None]

    def go_around(self, ev, td, at):
        if self._around is not None:
            self._around(ev, td, at)

    # ── export ──────────────────────────────────────────────────────────────
    def visible_order(self, tbl):
        src = self._shown_rows if tbl is self._tbl else self._shown_points
        out = []
        for r in range(tbl.rowCount()):
            cell = tbl.item(r, 0)
            i = cell.data(Qt.ItemDataRole.UserRole) if cell else None
            if i is not None and 0 <= i < len(src):
                out.append(src[i])
        return out

    def _export(self, timeline: bool):
        from evtx_tool.output.exporters import safe_csv_writer
        name = "system_activity_timeline.csv" if timeline else "system_activity_moments.csv"
        path, _ = QFileDialog.getSaveFileName(self, "Export System Activity", name, "CSV files (*.csv)")
        if not path:
            return
        tbl = self._tbl if timeline else self._tbl_pts
        try:
            self.write_csv(path, timeline)
        except Exception as exc:                                   # noqa: BLE001
            QMessageBox.critical(self, "Export Failed", f"Could not write CSV:\n{exc}")
            return
        QMessageBox.information(self, "Export Complete", f"Saved {tbl.rowCount():,} row(s) to:\n{path}")

    def _export_html(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export System Activity Report", "system_activity_report.html",
                                              "HTML files (*.html)")
        if not path:
            return
        try:
            info = self.write_html(path)
        except Exception as exc:                                   # noqa: BLE001
            logger.exception("System Activity HTML report failed")
            QMessageBox.critical(self, "Export Failed", f"Could not write the report:\n{exc}")
            return
        box = QMessageBox(self)
        box.setWindowTitle("Report Saved")
        box.setIcon(QMessageBox.Icon.Information)
        box.setText(f"Saved the System Activity report ({info['periods']:,} periods, {info['moments']:,} moments, "
                    f"{info['bytes'] / 1_000_000:.1f} MB) to:\n{path}")
        open_btn = box.addButton("Open", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Close", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is open_btn:
            from PySide6.QtCore import QUrl
            from PySide6.QtGui import QDesktopServices
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def write_html(self, path) -> dict:
        """The whole analysis (every computer, period, moment and raw event),
        not just the rows shown: the report has its own filters."""
        from evtx_tool.output.system_activity_report import write_html_report
        return write_html_report(path, self._res, self._events, digits=self._digits)

    def write_csv(self, path, timeline: bool):
        from evtx_tool.output.exporters import safe_csv_writer
        tbl = self._tbl if timeline else self._tbl_pts
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = safe_csv_writer(f)
            w.writerow(TIMELINE_HEADERS if timeline else MOMENT_HEADERS)
            for it in self.visible_order(tbl):
                w.writerow(self.row_cells(it) if timeline else self.point_cells(it))


class SystemActivityJMFetchWorker(QThread):
    """Juggernaut: load exactly the events the tool reads (ACTIVITY_SQL)."""

    finished = Signal(object, bool)      # (events, truncated) - Signal(object): see WiFi worker
    fetch_error = Signal(str, str)
    counted = Signal(int)

    def __init__(self, parquet_dir: str, parent=None, count_only: bool = False):
        super().__init__(parent)
        self._dir = parquet_dir
        self._count_only = count_only

    def run(self):
        import duckdb
        try:
            with open(os.path.join(self._dir, "parquet_manifest.json"), encoding="utf-8") as fh:
                shards = _json.load(fh)
        except FileNotFoundError:
            self.fetch_error.emit("manifest_missing", f"Parquet manifest not found in:\n{self._dir}")
            return
        except (OSError, ValueError) as exc:
            self.fetch_error.emit("manifest_read_error", f"Cannot read the Parquet manifest:\n{exc}")
            return
        if not shards:
            self.finished.emit([], False)
            return
        lst = "[" + ", ".join("'" + p.replace("'", "''") + "'" for p in shards) + "]"
        sql = (f"SELECT event_id, timestamp_utc, event_data_json, computer, source_file, channel, provider, "
               f"record_id, event_record_id FROM parquet_scan({lst}) WHERE {ACTIVITY_SQL} ORDER BY timestamp_utc")
        try:
            con = duckdb.connect()
            try:
                if self._count_only:
                    self.counted.emit(int(con.execute(f"SELECT count(*) FROM ({sql})").fetchone()[0]))
                    return
                rows = con.execute(sql).fetchall()
            finally:
                con.close()
        except Exception as exc:                                   # noqa: BLE001
            logger.error("System Activity JM query failed: %s", exc)
            self.fetch_error.emit("duckdb_query_error", str(exc))
            return
        events = []
        for eid, ts, ed_json, comp, sf, chan, prov, rid, erid in rows:
            try:
                ed = _json.loads(ed_json) if ed_json else {}
            except ValueError:
                ed = {}
            ts = str(ts or "")
            if ts and "T" not in ts:                      # Normal Mode's form (as the analysis materialiser)
                ts = ts.replace(" ", "T", 1) + "Z"
            events.append({"event_id": eid, "timestamp": ts, "event_data": ed, "computer": comp or "",
                           "source_file": sf or "", "channel": chan or "", "provider": prov or "",
                           "record_id": rid, "event_record_id": erid})
        self.finished.emit(events, False)
