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

    def __init__(self, result: dict, parent=None, around=None, digits: int = 0):
        super().__init__(parent)
        self._res = result
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
        cov.setStyleSheet("color:#666; font-size:8pt;")
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
        bar.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by activity, evidence or notes…")
        self._search.textChanged.connect(self._refresh)
        bar.addWidget(self._search, 1)
        root.addLayout(bar)

        self._tabs = QTabWidget()
        self._tbl = self._table(TIMELINE_HEADERS, [150, 60, 190, 165, 165, 120, 220, 220, 420])
        self._tbl_pts = self._table(MOMENT_HEADERS, [150, 165, 230, 520, 200])
        self._tabs.addTab(self._tbl, "Timeline")
        self._tabs.addTab(self._tbl_pts, "Moments")
        root.addWidget(self._tabs, 1)

        btns = QHBoxLayout()
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

    def point_cells(self, p):
        return [p["host"], fmt_time(p["time"], self._digits), p["what"], p["details"], p["evidence"]]

    def _refresh(self, *_):
        host, layers, text = self._filters()
        rows = [r for r in self._res.get("rows", []) if (host is None or r["host"] == host)
                and r["layer"] in layers]
        pts = [p for p in self._res.get("points", []) if host is None or p["host"] == host]
        if text:
            rows = [r for r in rows if any(text in str(c).lower() for c in self.row_cells(r))]
            pts = [p for p in pts if any(text in str(c).lower() for c in self.point_cells(p))]
        self._fill(self._tbl, rows, self.row_cells, lambda r: (r["start"], r["end"], r["duration"]),
                   lambda r: _COLOURS.get(r["state"]))
        self._fill(self._tbl_pts, pts, self.point_cells, lambda p: (p["time"], None, None), lambda p: None)
        self._shown_rows, self._shown_points = rows, pts
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
                if bg:
                    cell.setBackground(QColor(bg))
                tbl.setItem(i, c, cell)
        tbl.setSortingEnabled(True)

    def _summary(self, host):
        rows = [r for r in self._res.get("rows", []) if host is None or r["host"] == host]
        if not rows and not self._res.get("points"):
            self._lbl_summary.setText("<b>No power, screen or lock events found.</b>")
            return
        tot: dict = {}
        unknown = 0
        for r in rows:
            if r["duration"] is None:
                unknown += 1
                continue
            label = r["state"].split(" (session type")[0]
            tot[label] = tot.get(label, timedelta(0)) + r["duration"]
        order = ["On", "Screen on", "Screen off", "Sleep", "Hibernate", "Sleep or hibernate", "Modern Standby",
                 "Locked", "Screen saver", "Shut down", "Off"]
        parts = [f"{k}: <b>{fmt_secs(tot[k])}</b>" for k in order if k in tot]
        parts += [f"{k}: <b>{fmt_secs(v)}</b>" for k, v in tot.items() if k not in order]
        who = host if host is not None else f"{len(self._res.get('hosts', []))} computer(s)"
        txt = f"<b>{who}</b> &nbsp;│&nbsp; " + " &nbsp;│&nbsp; ".join(parts) if parts else f"<b>{who}</b>"
        if unknown:
            txt += (f" &nbsp;│&nbsp; <span style='color:#8a4800;'>{unknown} period(s) with an unknown start or "
                    f"end are not in these totals</span>")
        if host is not None and not any(r["layer"] == "Screen" for r in rows):
            txt += " &nbsp;│&nbsp; no screen data (no Kernel-Power 566 in these logs)"
        self._lbl_summary.setText(txt)

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
