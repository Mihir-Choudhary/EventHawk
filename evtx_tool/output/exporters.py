"""
Export matched events to CSV, JSON, XML, HTML, or PDF formats.

All exporters:
  - Stream-write to file (memory-efficient for large result sets)
  - Include all event fields + event_data sub-fields
  - UTF-8 encoded output

HTML exporter now includes:
  - MITRE ATT&CK summary table (if attack_summary provided)
  - IOC section (if iocs provided)
  - Correlation chains section (if chains provided)
  - Per-event ATT&CK badges
  - Case notes section (if case provided)
"""

from __future__ import annotations

import base64
import csv
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from evtx_tool.core._json_compat import fast_dumps

logger = logging.getLogger(__name__)

# ── WASM search module location ────────────────────────────────────────────────
# Built with: wasm-pack build --target no-modules --release --out-dir pkg
# (run from evtx_search_wasm/).  If the pkg/ dir is absent, export_html() falls
# back to the pure-JS pre-built search data (_SD) automatically.
_WASM_PKG_DIR = Path(__file__).resolve().parents[2] / "evtx_search_wasm" / "pkg"

# ── Shared helpers ─────────────────────────────────────────────────────────────

LEVEL_NAMES = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning",
               4: "Information", 5: "Verbose"}

def _flatten_event(event: dict) -> dict:
    """Flatten event_data into top-level keys for CSV/tabular export."""
    flat = {
        "RecordID":   event.get("record_id", ""),
        "EventID":    event.get("event_id", ""),
        "Timestamp":  event.get("timestamp", ""),
        "Channel":    event.get("channel", ""),
        "Provider":   event.get("provider", ""),
        "Computer":   event.get("computer", ""),
        "Level":      event.get("level", ""),
        "LevelName":  event.get("level_name", ""),
        "Task":       event.get("task", ""),
        "Keywords":   event.get("keywords", ""),
        "UserID":     event.get("user_id", ""),
        "ProcessID":  event.get("process_id", ""),
        "SourceFile": os.path.basename(event.get("source_file", "")),
        "ATT&CK":     "; ".join(
            f"{t['tid']}:{t['name']}"
            for t in (event.get("attack_tags") or [])
        ),
    }
    ed = event.get("event_data", {}) or {}
    if isinstance(ed, dict):
        for k, v in ed.items():
            flat[f"ED_{k}"] = str(v) if v is not None else ""
    return flat


def _collect_csv_headers(events: list[dict]) -> list[str]:
    """Collect all unique column names from all events."""
    base_keys = ["RecordID", "EventID", "Timestamp", "Channel", "Provider",
                 "Computer", "Level", "LevelName", "Task", "Keywords",
                 "UserID", "ProcessID", "SourceFile", "ATT&CK"]
    extra_keys: list[str] = []
    seen_extra = set()
    for ev in events:
        ed = ev.get("event_data", {}) or {}
        for k in ed:
            key = f"ED_{k}"
            if key not in seen_extra:
                seen_extra.add(key)
                extra_keys.append(key)
    return base_keys + sorted(extra_keys)


# ── CSV ────────────────────────────────────────────────────────────────────────

def export_csv(events: list[dict], filepath: str, **_) -> int:
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    # FINDING-18: replace _collect_csv_headers() (separate O(n) pre-pass with
    # list+set overhead) with a tight set comprehension — same O(n) complexity
    # but avoids the extra function call, list.append() loop, and intermediate
    # list construction.
    base_keys = ["RecordID", "EventID", "Timestamp", "Channel", "Provider",
                 "Computer", "Level", "LevelName", "Task", "Keywords",
                 "UserID", "ProcessID", "SourceFile", "ATT&CK"]
    headers = base_keys + sorted({
        f"ED_{k}"
        for ev in events
        for k in (ev.get("event_data") or {})
    })
    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        count = 0
        for ev in events:
            writer.writerow(_flatten_event(ev))
            count += 1
    logger.info("CSV export: %d events -> %s", count, filepath)
    return count


# ── JSON ───────────────────────────────────────────────────────────────────────

def export_json(events: list[dict], filepath: str, **_) -> int:
    # Perf fix #7: stream-write per-event instead of json.dump(entire_list).
    # Reduces peak memory from 2x events list to ~1x (no serialization buffer).
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("[\n")
        for i, ev in enumerate(events):
            if i > 0:
                f.write(",\n")
            f.write(fast_dumps(ev, indent=2))
        f.write("\n]\n")
    logger.info("JSON export: %d events -> %s", len(events), filepath)
    return len(events)


# ── XML ────────────────────────────────────────────────────────────────────────

def export_xml(events: list[dict], filepath: str, **_) -> int:
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    try:
        from lxml import etree
        _export_xml_lxml(events, filepath)
    except ImportError:
        _export_xml_stdlib(events, filepath)
    logger.info("XML export: %d events -> %s", len(events), filepath)
    return len(events)


def _export_xml_lxml(events: list[dict], filepath: str) -> None:
    from lxml import etree
    root = etree.Element("EVTXParserResults")
    root.set("generated", datetime.now(timezone.utc).isoformat())
    root.set("totalEvents", str(len(events)))
    for ev in events:
        event_el = etree.SubElement(root, "Event")
        sys_el   = etree.SubElement(event_el, "System")
        for tag, key in [("RecordID","record_id"),("EventID","event_id"),
                         ("Timestamp","timestamp"),("Channel","channel"),
                         ("Provider","provider"),("Computer","computer"),
                         ("Level","level"),("LevelName","level_name"),
                         ("Task","task"),("Keywords","keywords"),
                         ("UserID","user_id")]:
            el = etree.SubElement(sys_el, tag)
            el.text = str(ev.get(key, "") or "")
        src_el = etree.SubElement(sys_el, "SourceFile")
        src_el.text = os.path.basename(ev.get("source_file", ""))
        tags = ev.get("attack_tags") or []
        if tags:
            atk_el = etree.SubElement(event_el, "ATTACKTags")
            for t in tags:
                te = etree.SubElement(atk_el, "Technique")
                te.set("id", t.get("tid",""))
                te.set("tactic", t.get("tactic",""))
                te.text = t.get("name","")
        ed = ev.get("event_data", {}) or {}
        if ed:
            ed_el = etree.SubElement(event_el, "EventData")
            for k, v in ed.items():
                data_el = etree.SubElement(ed_el, "Data")
                data_el.set("Name", str(k))
                data_el.text = str(v) if v is not None else ""
    etree.ElementTree(root).write(filepath, xml_declaration=True,
                                  encoding="utf-8", pretty_print=True)


def _export_xml_stdlib(events: list[dict], filepath: str) -> None:
    def _esc(s):
        return (str(s).replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace('"',"&quot;"))
    with open(filepath, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n')
        f.write(f'<EVTXParserResults generated="{datetime.now(timezone.utc).isoformat()}" '
                f'totalEvents="{len(events)}">\n')
        for ev in events:
            f.write("  <Event>\n    <System>\n")
            for tag, key in [("RecordID","record_id"),("EventID","event_id"),
                              ("Timestamp","timestamp"),("Channel","channel"),
                              ("Provider","provider"),("Computer","computer"),
                              ("Level","level"),("LevelName","level_name"),
                              ("Task","task"),("Keywords","keywords"),("UserID","user_id")]:
                f.write(f"      <{tag}>{_esc(ev.get(key,''))}</{tag}>\n")
            f.write(f"      <SourceFile>{_esc(os.path.basename(ev.get('source_file','')))}</SourceFile>\n")
            f.write("    </System>\n")
            # BUG 21 fix: write ATT&CK tags in stdlib path to match lxml output
            tags = ev.get("attack_tags") or []
            if tags:
                f.write("    <ATTACKTags>\n")
                for t in tags:
                    f.write(
                        f'      <Technique id="{_esc(t.get("tid",""))}"'
                        f' tactic="{_esc(t.get("tactic",""))}">'
                        f'{_esc(t.get("name",""))}</Technique>\n'
                    )
                f.write("    </ATTACKTags>\n")
            ed = ev.get("event_data", {}) or {}
            if ed:
                f.write("    <EventData>\n")
                for k, v in ed.items():
                    f.write(f'      <Data Name="{_esc(k)}">{_esc(v)}</Data>\n')
                f.write("    </EventData>\n")
            f.write("  </Event>\n")
        f.write("</EVTXParserResults>\n")


# ── HTML ───────────────────────────────────────────────────────────────────────

LEVEL_BADGE_CLASS = {
    "Critical":    "badge-critical",
    "Error":       "badge-error",
    "Warning":     "badge-warning",
    "Information": "badge-info",
    "Verbose":     "badge-verbose",
    "LogAlways":   "badge-logalways",
}

SUSPICIOUS_EVENT_IDS = {
    4625, 4648, 4697, 4698, 4702, 4720, 4740, 4776, 4768, 4769,
    7045, 1102, 4719, 4735, 4728, 4732, 4756, 4771, 4777, 1, 8, 10,
}

# FINDING-26: import canonical constants from attack_mapping instead of
# duplicating them here — prevents silent divergence between the two copies.
from evtx_tool.analysis.attack_mapping import TACTIC_ORDER, TACTIC_COLORS  # noqa: E402

SEV_COLORS = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f39c12",
    "low":      "#2980b9",
}


# ── WASM / JS search helpers ───────────────────────────────────────────────────

def _build_search_string(ev: dict) -> str:
    """
    Build a compact, pre-lowercased search string for a single event.

    Perf fix #6: per-event version (no intermediate list). Called from
    stream-writing loop in export_html().

    Fields included (in order):
        event_id, timestamp (truncated), channel, provider, computer,
        level_name, source filename, ATT&CK tids + names + tactics,
        all event_data values (first 30, capped at 200 chars each).
    """
    ed   = ev.get("event_data", {}) or {}
    tags = ev.get("attack_tags") or []

    parts: list[str] = [
        str(ev.get("event_id", "")),
        (ev.get("timestamp", "") or "")[:19].replace("T", " "),
        ev.get("channel",   "") or "",
        ev.get("provider",  "") or "",
        ev.get("computer",  "") or "",
        ev.get("level_name","") or "",
        os.path.basename(ev.get("source_file", "") or ""),
        ev.get("user_id",   "") or "",
    ]
    for tag in tags:
        parts.append(tag.get("tid",    ""))
        parts.append(tag.get("name",   ""))
        parts.append(tag.get("tactic", ""))

    if isinstance(ed, dict):
        for v in list(ed.values())[:30]:
            if v is not None:
                parts.append(str(v)[:200])

    return " ".join(p for p in parts if p).lower()


def _build_search_data(events: list[dict]) -> list[str]:
    """
    Build compact, pre-lowercased search strings for the JS/WASM search index.
    Kept for backward compatibility (used by WASM init path if needed).
    """
    return [_build_search_string(ev) for ev in events]


def _load_wasm_assets() -> tuple[str | None, str | None]:
    """
    Try to load the pre-built WASM binary and its JS glue file.

    Returns ``(wasm_b64, glue_js)`` on success, ``(None, None)`` if the pkg/
    directory is missing or files cannot be read (e.g. not yet built).
    """
    try:
        wasm_file = _WASM_PKG_DIR / "evtx_search_wasm_bg.wasm"
        js_file   = _WASM_PKG_DIR / "evtx_search_wasm.js"
        if not wasm_file.exists() or not js_file.exists():
            return None, None
        wasm_b64 = base64.b64encode(wasm_file.read_bytes()).decode("ascii")
        glue_js  = js_file.read_text(encoding="utf-8")
        return wasm_b64, glue_js
    except Exception as exc:
        logger.debug("WASM assets not loaded (%s) — using JS fallback", exc)
        return None, None


def _wasm_init_block(wasm_b64: str, glue_js: str) -> str:
    """
    Return an HTML fragment that inlines the WASM binary and initialises the
    ``SearchIndex`` from ``window._SD`` (already written by export_html).

    Uses the ``--target no-modules`` wasm-bindgen output which sets up a
    ``window.wasm_bindgen`` global (classic <script>, no ES-module import()
    required — safe for self-contained single-file HTML reports).
    """
    return (
        # 1. Glue JS — sets up window.wasm_bindgen init function
        "<script>\n" + glue_js + "\n</script>\n"
        # 2. Async init — decode base64, compile, build SearchIndex from _SD
        "<script>\n"
        "(async function() {\n"
        "  try {\n"
        f"    var _wb64='{wasm_b64}';\n"
        "    var _wbytes=Uint8Array.from(atob(_wb64),function(c){return c.charCodeAt(0);});\n"
        "    await wasm_bindgen(_wbytes);\n"
        "    window._searchIdx=new wasm_bindgen.SearchIndex(JSON.stringify(window._SD||[]));\n"
        "    window._wasmReady=true;\n"
        "    var badge=document.getElementById('wasmBadge');\n"
        "    if(badge)badge.style.display='inline';\n"
        "    var sv=document.getElementById('searchInput');\n"
        "    if(sv&&sv.value)sv.dispatchEvent(new Event('input'));\n"
        "  } catch(e){console.warn('[evtx-wasm] init failed, using JS fallback:',e);}\n"
        "})();\n"
        "</script>\n"
    )


_HTML_STYLE = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
h1 { color: #4fc3f7; border-bottom: 2px solid #4fc3f7; padding-bottom: 10px; margin-bottom: 16px; font-size: 1.6em; }
h2 { color: #4fc3f7; font-size: 1.1em; margin: 18px 0 8px 0; }
h3 { color: #90a4ae; font-size: 0.95em; margin: 12px 0 6px 0; }
.meta { color: #8b949e; font-size: 0.85em; margin-bottom: 18px; }
.section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 20px; }

/* Stat cards */
.stats { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 0; }
.stat-card { background: #0d1117; border: 1px solid #4fc3f7; border-radius: 8px; padding: 12px 18px; min-width: 130px; }
.stat-card .num { font-size: 1.8em; font-weight: bold; color: #4fc3f7; }
.stat-card .label { color: #8b949e; font-size: 0.8em; margin-top: 2px; }

/* Tabs */
.tab-bar { display: flex; gap: 4px; margin-bottom: 14px; flex-wrap: wrap; }
.tab-btn { padding: 5px 14px; border: 1px solid #30363d; border-radius: 4px 4px 0 0;
           background: #0d1117; color: #8b949e; cursor: pointer; font-size: 0.85em;
           border-bottom: none; }
.tab-btn.active { background: #161b22; color: #4fc3f7; border-color: #4fc3f7; }
.tab-content { display: none; }
.tab-content.active { display: block; }

/* ATT&CK heatmap */
.attack-grid { display: flex; flex-wrap: wrap; gap: 6px; }
.attack-cell { padding: 6px 10px; border-radius: 4px; font-size: 0.78em; color: white; font-weight: bold; cursor: default; }
.attack-tactic { background: #21262d; border: 1px solid #30363d; padding: 8px 12px; border-radius: 6px; min-width: 180px; flex: 1; }
.attack-tactic h4 { font-size: 0.8em; color: #8b949e; margin-bottom: 6px; }
.technique-tag { display: inline-block; margin: 2px; padding: 2px 7px; border-radius: 3px; font-size: 0.75em; font-weight: bold; color: white; }

/* IOC */
.ioc-grid { display: flex; flex-wrap: wrap; gap: 16px; }
.ioc-col { flex: 1; min-width: 200px; }
.ioc-col h4 { font-size: 0.82em; color: #8b949e; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em; }
.ioc-item { background: #0d1117; border: 1px solid #21262d; border-radius: 3px;
            padding: 2px 8px; margin-bottom: 3px; font-family: monospace;
            font-size: 0.8em; color: #79c0ff; word-break: break-all; }

/* Chains */
.chain { border-left: 4px solid #4fc3f7; background: #161b22; border-radius: 4px; padding: 10px 14px; margin-bottom: 10px; }
.chain.sev-critical { border-color: #c0392b; } .chain.sev-high { border-color: #e67e22; }
.chain.sev-medium   { border-color: #f39c12; } .chain.sev-low  { border-color: #2980b9; }
.chain-title { font-weight: bold; color: #e6edf3; font-size: 0.92em; }
.chain-meta  { font-size: 0.78em; color: #8b949e; margin: 3px 0; }
.chain-desc  { font-size: 0.83em; color: #c9d1d9; margin-top: 4px; }
.sev-badge   { display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 0.75em; font-weight: bold; color: white; margin-left: 8px; }
.sev-badge.critical { background: #c0392b; } .sev-badge.high   { background: #e67e22; }
.sev-badge.medium   { background: #f39c12; color: #111; } .sev-badge.low { background: #2980b9; }

/* Search bar */
.search-bar { width: 100%; padding: 8px 12px; background: #161b22; border: 1px solid #4fc3f7;
              color: #c9d1d9; border-radius: 4px; margin-bottom: 6px; font-size: 0.9em; }
.search-hint { font-size: 0.75em; color: #586069; margin-bottom: 10px; line-height: 1.5; }
.search-hint code { background: #21262d; padding: 1px 5px; border-radius: 3px; color: #79c0ff; font-family: monospace; }

/* Event table */
table { width: 100%; border-collapse: collapse; font-size: 0.83em; }
th { background: #21262d; color: #4fc3f7; padding: 8px 7px; text-align: left;
     position: sticky; top: 0; z-index: 2; white-space: nowrap; cursor: pointer; user-select: none; }
th:hover { background: #2a313a; }
th.no-sort { cursor: default; } th.no-sort:hover { background: #21262d; }
th .sort-arrow { font-size: 0.72em; margin-left: 3px; color: #586069; }
th .sort-arrow.active { color: #4fc3f7; }
td { padding: 5px 7px; border-bottom: 1px solid #21262d; }
tr.event-row:hover { background: #1c2128; }
tr.suspicious { background: #1c1208; } tr.suspicious:hover { background: #261a0a; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 0.78em; font-weight: bold; }
.badge-critical { background: #b71c1c; color: white; } .badge-error    { background: #c62828; color: white; }
.badge-warning  { background: #bf360c; color: white; } .badge-info     { background: #1565c0; color: white; }
.badge-verbose  { background: #37474f; color: #b0bec5; } .badge-logalways { background: #455a64; color: white; }
.event-id { font-family: monospace; font-weight: bold; color: #79c0ff; }
.ts { color: #8b949e; font-family: monospace; font-size: 0.82em; white-space: nowrap; }

/* Detail / expand rows — increased font sizes */
.detail-row td { background: #0d1117; white-space: pre-wrap; font-family: 'Consolas', 'Courier New', monospace;
                 font-size: 1em; color: #c9d1d9; padding: 14px 20px; line-height: 1.65; }
.detail-row .detail-section { margin-bottom: 12px; }
.detail-row .detail-section-title { color: #4fc3f7; font-weight: bold; font-size: 0.92em;
                                    margin-bottom: 6px; border-bottom: 1px solid #21262d; padding-bottom: 3px; }
.detail-row .detail-key { color: #8cf; font-weight: bold; display: inline-block; min-width: 180px; }
.detail-row .detail-val { color: #e6edf3; font-size: 1em; }

/* Description box in detail rows */
.desc-box { background: #141e2e; border-left: 3px solid #4fc3f7; border-radius: 0 4px 4px 0;
            padding: 10px 16px; margin-bottom: 14px; font-size: 1.05em;
            font-family: 'Segoe UI', Arial, sans-serif; color: #dae8f5;
            line-height: 1.75; white-space: normal; }
.desc-box-title { font-size: 0.82em; color: #4fc3f7; font-weight: bold;
                  letter-spacing: 0.04em; margin-bottom: 5px; font-family: 'Segoe UI', Arial, sans-serif; }

.expand-btn { cursor: pointer; color: #4fc3f7; border: none; background: none; font-size: 0.9em; padding: 0 4px; }
.atk-badge { display: inline-block; margin: 1px; padding: 1px 6px; border-radius: 3px;
             font-size: 0.7em; font-weight: bold; color: white; cursor: default; opacity: 0.9; }
.case-note { background: #161b22; border-left: 3px solid #4fc3f7; padding: 6px 10px; margin-bottom: 6px; font-size: 0.85em; }
.bm-tag { display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 0.78em; font-weight: bold; margin-right: 6px; }
.bm-tag.confirmed  { background: #27ae60; color: white; } .bm-tag.suspicious { background: #e67e22; color: white; }
.bm-tag.benign     { background: #2980b9; color: white; } .bm-tag.follow-up  { background: #8e44ad; color: white; }

/* Search counter + WASM badge */
.search-counter { font-size: 0.82em; color: #8b949e; margin-left: 10px; vertical-align: middle; }
.wasm-badge { display: none; background: #1abc9c; color: #0d1117; font-size: 0.72em;
              font-weight: bold; padding: 1px 7px; border-radius: 3px;
              vertical-align: middle; margin-left: 8px; letter-spacing: 0.03em; }

/* Filter toolbar */
.filter-toolbar { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; align-items: center; }
.filter-toolbar label { color: #8b949e; font-size: 0.8em; white-space: nowrap; }
.col-filter-select { background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
                     border-radius: 4px; padding: 4px 8px; font-size: 0.82em; min-width: 100px; }
.col-filter-select:focus { border-color: #4fc3f7; outline: none; }
.filter-toggle { padding: 4px 12px; border: 1px solid #30363d; border-radius: 4px;
                 background: #0d1117; color: #8b949e; cursor: pointer; font-size: 0.8em;
                 transition: border-color 0.15s, color 0.15s, background 0.15s; white-space: nowrap; }
.filter-toggle:hover { border-color: #4fc3f7; color: #c9d1d9; }
.filter-toggle.on-susp { background: #3a1a00; border-color: #e67e22; color: #e67e22; }
.filter-toggle.on-atk  { background: #142714; border-color: #27ae60; color: #27ae60; }
.filter-toggle.on-ps   { background: #2a0a0a; border-color: #ff6b6b; color: #ff6b6b; }
.filter-reset { padding: 4px 12px; border: 1px solid #586069; border-radius: 4px;
                background: transparent; color: #586069; cursor: pointer; font-size: 0.8em; }
.filter-reset:hover { border-color: #c0392b; color: #c0392b; }
.time-input { background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
              border-radius: 4px; padding: 3px 8px; font-size: 0.8em; color-scheme: dark; }
.time-input:focus { border-color: #4fc3f7; outline: none; }
.active-filter-badge { background: #4fc3f7; color: #0d1117; font-size: 0.72em;
                       font-weight: bold; padding: 2px 9px; border-radius: 10px; margin-left: 4px; }
</style>
"""

_HTML_SCRIPT = r"""
<script>
// ─── Tab switching ────────────────────────────────────────────────────────────
function switchTab(sectionId, tabId, btn) {
  document.querySelectorAll('#'+sectionId+' .tab-content').forEach(function(t){t.classList.remove('active');});
  document.querySelectorAll('#'+sectionId+' .tab-btn').forEach(function(b){b.classList.remove('active');});
  document.getElementById(tabId).classList.add('active');
  if (btn) btn.classList.add('active');
}

// ─── Unified Filter State ─────────────────────────────────────────────────────
// ALL filters (dropdowns, toggles, text, time range) live here.
// applyFilters() reads _F and shows/hides rows in one pass.
var _F = {
  text:'', level:'', channel:'', computer:'', eid:'', tactic:'',
  suspOnly:false, hasAttck:false, hasPS:false,
  timeFrom:'', timeTo:''
};
var _debounceTimer = null;

// ─── Per-row non-text filter check ───────────────────────────────────────────
function _checkRow(row) {
  var d = row.dataset;
  if (_F.level    && d.level    !== _F.level)    return false;
  if (_F.channel  && d.channel  !== _F.channel)  return false;
  if (_F.computer && d.computer !== _F.computer) return false;
  if (_F.eid      && d.eid      !== _F.eid)      return false;
  if (_F.tactic) {
    var tacticList = (d.tactics || '').split(';');
    if (tacticList.indexOf(_F.tactic) === -1) return false;
  }
  if (_F.suspOnly && d.susp  !== '1') return false;
  if (_F.hasAttck && d.hasAtk !== '1') return false;
  if (_F.hasPS    && d.hasPs  !== '1') return false;
  if (_F.timeFrom || _F.timeTo) {
    var ts = d.ts || '';
    // datetime-local produces "YYYY-MM-DDTHH:MM"; compare as prefix of ISO ts
    if (_F.timeFrom && ts.slice(0, _F.timeFrom.length) < _F.timeFrom) return false;
    if (_F.timeTo   && ts.slice(0, _F.timeTo.length)   > _F.timeTo)   return false;
  }
  return true;
}

// ─── Core apply function ──────────────────────────────────────────────────────
// 3-tier text search:
//   Tier 1 (WASM)  : window._wasmReady + window._searchIdx  — fastest (Rust)
//   Tier 2 (JS)    : window._SD pre-built strings           — fast   (no DOM)
//   Tier 3 (DOM)   : textContent scan                        — always works
// Field-specific syntax: eid:4624  level:error  computer:srv  tactic:execution  tid:T1059
function applyFilters() {
  var rows = document.querySelectorAll('tr.event-row');
  var total = rows.length;

  // Step 1: collect indices passing all non-text filters
  var candidateSet = new Set();
  rows.forEach(function(row) {
    if (_checkRow(row)) candidateSet.add(+row.dataset.idx);
  });

  // Step 2: parse text query — extract field:value tokens, then general terms
  var rawQ = _F.text.toLowerCase().trim();
  var fieldFilters = {};
  var generalTerms = [];
  if (rawQ) {
    var remaining = rawQ.replace(/(\w+):(\S+)/g, function(m, field, val) {
      fieldFilters[field] = val; return '';
    }).trim();
    if (remaining) generalTerms = remaining.split(/\s+/).filter(Boolean);

    // Apply field-specific filters against candidateSet
    var _del = function(condFn) {
      candidateSet.forEach(function(i) {
        var row = document.querySelector('tr.event-row[data-idx="' + i + '"]');
        if (row && !condFn(row)) candidateSet.delete(i);
      });
    };
    if (fieldFilters.eid) {
      var eids = fieldFilters.eid.split(',');
      _del(function(r){ return eids.indexOf(r.dataset.eid) !== -1; });
    }
    if (fieldFilters.level)    _del(function(r){ return (r.dataset.level    ||'').toLowerCase().indexOf(fieldFilters.level)    !== -1; });
    if (fieldFilters.computer) _del(function(r){ return (r.dataset.computer ||'').toLowerCase().indexOf(fieldFilters.computer) !== -1; });
    if (fieldFilters.channel)  _del(function(r){ return (r.dataset.channel  ||'').toLowerCase().indexOf(fieldFilters.channel)  !== -1; });
    if (fieldFilters.tactic)   _del(function(r){ return (r.dataset.tactics  ||'').toLowerCase().indexOf(fieldFilters.tactic)   !== -1; });
    if (fieldFilters.tid)      _del(function(r){ return (r.dataset.tids     ||'').toLowerCase().indexOf(fieldFilters.tid)      !== -1; });
  }

  // Step 3: apply general text search on remaining candidates
  var finalSet;
  if (!generalTerms.length) {
    finalSet = candidateSet;
  } else {
    finalSet = new Set();
    var candidateArr = Array.from(candidateSet);

    // Tier 1: WASM — compute text hits, intersect with candidateSet
    if (window._wasmReady && window._searchIdx) {
      try {
        var wasmHits = new Set(JSON.parse(window._searchIdx.filter(generalTerms.join(' '))));
        candidateArr.forEach(function(i){ if (wasmHits.has(i)) finalSet.add(i); });
        _showRows(finalSet, total, rows); return;
      } catch(e) { /* fall through */ }
    }

    // Tier 2: pre-built JS search strings
    if (window._SD && window._SD.length) {
      candidateArr.forEach(function(i) {
        var s = window._SD[i] || '';
        if (generalTerms.every(function(t){ return s.indexOf(t) !== -1; })) finalSet.add(i);
      });
      _showRows(finalSet, total, rows); return;
    }

    // Tier 3: DOM scan fallback
    candidateArr.forEach(function(i) {
      var row = document.querySelector('tr.event-row[data-idx="' + i + '"]');
      if (!row) return;
      var s = row.textContent.toLowerCase();
      if (generalTerms.every(function(t){ return s.indexOf(t) !== -1; })) finalSet.add(i);
    });
  }
  _showRows(finalSet, total, rows);
}

function _showRows(matchSet, total, rows) {
  rows.forEach(function(row) {
    var i = +row.dataset.idx, show = matchSet.has(i);
    row.style.display = show ? '' : 'none';
    if (!show) { var d = document.getElementById('detail-'+i); if(d) d.style.display='none'; }
  });
  var ctr = document.getElementById('searchCounter');
  if (ctr) {
    var n = matchSet.size;
    ctr.textContent = n === total ? '' : n.toLocaleString()+'\u00a0/\u00a0'+total.toLocaleString()+' shown';
  }
  _updateFilterBadge();
}

// ─── Active filter badge ──────────────────────────────────────────────────────
function _updateFilterBadge() {
  var n = [_F.text, _F.level, _F.channel, _F.computer, _F.eid, _F.tactic,
           _F.suspOnly, _F.hasAttck, _F.hasPS].filter(Boolean).length
        + ((_F.timeFrom || _F.timeTo) ? 1 : 0);
  var el = document.getElementById('activeFilterBadge');
  if (el) { el.textContent = n ? n+' filter'+(n>1?'s':'')+' active' : ''; el.style.display = n?'inline':'none'; }
}

// ─── Toggle buttons ───────────────────────────────────────────────────────────
function toggleFilter(key, btn, onClass) {
  _F[key] = !_F[key];
  btn.classList.toggle(onClass, _F[key]);
  applyFilters();
}

// ─── Reset all filters ────────────────────────────────────────────────────────
function resetFilters() {
  _F = { text:'', level:'', channel:'', computer:'', eid:'', tactic:'',
         suspOnly:false, hasAttck:false, hasPS:false, timeFrom:'', timeTo:'' };
  var el;
  ['filterLevel','filterChannel','filterComputer','filterEventID','filterTactic'].forEach(function(id){
    el=document.getElementById(id); if(el) el.value='';
  });
  el=document.getElementById('searchInput'); if(el) el.value='';
  ['timeFrom','timeTo'].forEach(function(id){ el=document.getElementById(id); if(el) el.value=''; });
  document.querySelectorAll('.filter-toggle').forEach(function(b){
    b.classList.remove('on-susp','on-atk','on-ps');
  });
  applyFilters();
}

// ─── Search input wiring ──────────────────────────────────────────────────────
document.getElementById('searchInput').addEventListener('input', function() {
  _F.text = this.value.trim();
  clearTimeout(_debounceTimer);
  _debounceTimer = setTimeout(applyFilters, _F.text.length > 1 ? 80 : 220);
});

// ─── Expand/collapse detail rows ──────────────────────────────────────────────
function toggleDetail(idx) {
  var det = document.getElementById('detail-' + idx);
  if (!det) return;
  var parentRow = document.querySelector('tr.event-row[data-idx="' + idx + '"]');
  if (parentRow && parentRow.style.display === 'none') return;
  det.style.display = det.style.display === 'none' ? '' : 'none';
}

// ─── Column Sorting ───────────────────────────────────────────────────────────
// Uses data attributes for reliable sort (data-ts, data-eid, data-level, data-atk-count)
// instead of parsing cell textContent — avoids badge HTML interfering with values.
var _sortCol = -1, _sortDir = 0;
var _LEVEL_ORDER = {Critical:0, Error:1, Warning:2, Information:3, Verbose:4, LogAlways:5};

function sortTable(colIdx) {
  _sortDir = (_sortCol === colIdx) ? (_sortDir + 1) % 3 : 1;
  _sortCol = colIdx;
  document.querySelectorAll('th .sort-arrow').forEach(function(a){
    a.classList.remove('active'); a.textContent = '\u2195';
  });
  var th = document.querySelectorAll('thead th')[colIdx];
  if (th) {
    var arrow = th.querySelector('.sort-arrow');
    if (arrow && _sortDir > 0) {
      arrow.classList.add('active');
      arrow.textContent = _sortDir === 1 ? '\u25B2' : '\u25BC';
    }
  }
  var tbody = document.querySelector('tbody');
  if (!tbody) return;
  var rows = Array.from(tbody.querySelectorAll('tr.event-row'));
  if (_sortDir === 0) {
    rows.sort(function(a,b){ return (+a.dataset.idx)-(+b.dataset.idx); });
  } else {
    var dir = _sortDir === 1 ? 1 : -1;
    rows.sort(function(a, b) {
      var av, bv;
      switch (colIdx) {
        case 1: // Timestamp — ISO string, lexicographic = chronological
          return dir * (a.dataset.ts||'').localeCompare(b.dataset.ts||'');
        case 2: // EventID — numeric
          return dir * ((+(a.dataset.eid||0)) - (+(b.dataset.eid||0)));
        case 3: // Level — by severity order (Critical first on asc)
          return dir * ((_LEVEL_ORDER[a.dataset.level]??99) - (_LEVEL_ORDER[b.dataset.level]??99));
        case 7: // ATT&CK — by technique tag count
          return dir * ((+(a.dataset.atkCount||0)) - (+(b.dataset.atkCount||0)));
        default:
          av = (a.cells[colIdx] ? a.cells[colIdx].textContent : '').trim();
          bv = (b.cells[colIdx] ? b.cells[colIdx].textContent : '').trim();
          var n = parseFloat(av) - parseFloat(bv);
          if (!isNaN(n)) return dir * n;
          return dir * av.localeCompare(bv);
      }
    });
  }
  rows.forEach(function(row) {
    var det = document.getElementById('detail-' + row.dataset.idx);
    tbody.appendChild(row);
    if (det) tbody.appendChild(det);
  });
}
</script>
"""


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _fmt_ts(ts: str) -> str:
    return ts.replace("T", " ").replace("Z", "").replace(" UTC", "")[:19] if ts else ""


def export_html(
    events: list[dict],
    filepath: str,
    attack_summary: dict | None = None,
    iocs:           dict | None = None,
    chains:         list[dict] | None = None,
    **_,
) -> int:
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

    # ── Quick stats ────────────────────────────────────────────────────────
    by_eid:   dict[int, int] = {}
    by_level: dict[str, int] = {}
    by_comp:  dict[str, int] = {}
    for ev in events:
        eid = ev.get("event_id", 0)
        by_eid[eid] = by_eid.get(eid, 0) + 1
        lvl = ev.get("level_name", "Information")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        comp = ev.get("computer", "")
        if comp:
            by_comp[comp] = by_comp.get(comp, 0) + 1

    suspicious_count = sum(1 for ev in events if ev.get("event_id", 0) in SUSPICIOUS_EVENT_IDS)
    ps_events        = sum(1 for ev in events if ev.get("event_id") == 4104)
    chain_count      = len(chains) if chains else 0
    ioc_count        = sum(v for k, v in (iocs or {}).get("summary", {}).items()
                           if k != "summary" and isinstance(v, int))

    # ── Pre-pass: collect all tactics and tids for the tactic dropdown ────
    all_tactics: list[str] = []
    _seen_tactics: set[str] = set()
    for _ev in events:
        for _tag in (_ev.get("attack_tags") or []):
            t = _tag.get("tactic", "")
            if t and t not in _seen_tactics:
                _seen_tactics.add(t)
                all_tactics.append(t)

    # ── Load event description function once (graceful if unavailable) ────
    try:
        from evtx_tool.analysis.event_descriptions import get_event_description as _get_desc
    except Exception:
        _get_desc = None  # type: ignore[assignment]

    with open(filepath, "w", encoding="utf-8") as f:

        # ── Head ──────────────────────────────────────────────────────────
        f.write("<!DOCTYPE html><html lang='en'><head>")
        f.write("<meta charset='utf-8'>")
        f.write("<meta name='viewport' content='width=device-width,initial-scale=1'>")
        title_str = "EventHawk — Report"
        f.write(f"<title>{_esc(title_str)}</title>")
        f.write(_HTML_STYLE)
        f.write("</head><body>\n")

        # ── Header ────────────────────────────────────────────────────────
        f.write(f"<h1>&#128269; {_esc(title_str)}</h1>\n")
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        f.write(f"<div class='meta'>Generated: {generated} | "
                f"Total Events: {len(events):,}</div>\n")

        # ── Stat Cards ────────────────────────────────────────────────────
        f.write("<div class='section'><div class='stats'>\n")
        stat_cards = [
            ("Total Events",       f"{len(events):,}"),
            ("Suspicious Events",  f"{suspicious_count:,}"),
            ("Unique Event IDs",   f"{len(by_eid):,}"),
            ("Unique Computers",   f"{len(by_comp):,}"),
            ("Attack Chains",      f"{chain_count:,}"),
            ("IOCs Extracted",     f"{ioc_count:,}"),
            ("PS Script Events",   f"{ps_events:,}"),
        ]
        for label, num in stat_cards:
            f.write(f"<div class='stat-card'>"
                    f"<div class='num'>{num}</div>"
                    f"<div class='label'>{label}</div></div>\n")
        f.write("</div></div>\n")

        # ── MITRE ATT&CK Section ──────────────────────────────────────────
        if attack_summary and attack_summary.get("by_tactic"):
            f.write("<div class='section'>\n")
            f.write("<h2>&#127919; MITRE ATT&amp;CK Coverage</h2>\n")
            total_tagged = attack_summary.get("total_tagged", 0)
            f.write(f"<div class='meta'>{total_tagged:,} events mapped to "
                    f"{len(attack_summary['by_tactic'])} tactics | "
                    f"{len(attack_summary['by_technique'])} unique techniques</div>\n")

            # Tactic grid
            f.write("<div class='attack-grid'>\n")
            by_tactic    = attack_summary.get("by_tactic", {})
            by_technique = attack_summary.get("by_technique", {})

            for tactic in TACTIC_ORDER:
                cnt = by_tactic.get(tactic, 0)
                if not cnt:
                    continue
                color = TACTIC_COLORS.get(tactic, "#555")
                f.write(f"<div class='attack-tactic'>\n")
                f.write(f"<h4 style='color:{color}'>{_esc(tactic)} "
                        f"<span style='color:#4fc3f7'>({cnt:,})</span></h4>\n")
                # List techniques under this tactic
                for tid, info in sorted(by_technique.items(),
                                        key=lambda x: -x[1]["count"]):
                    if info["tactic"] != tactic:
                        continue
                    intensity = min(255, 80 + int(info["count"] / max(total_tagged,1) * 1200))
                    cnt_val  = info['count']
                    name_val = info['name']
                    opacity  = min(1.0, 0.5 + cnt_val / max(total_tagged, 1) * 2)
                    f.write(
                        f"<span class='technique-tag' "
                        f"style='background:{color};opacity:{opacity:.2f}' "
                        f"title='{_esc(name_val)} ({cnt_val} hits)'>"
                        f"{_esc(tid)}</span>\n"
                    )
                f.write("</div>\n")
            f.write("</div>\n")  # attack-grid
            f.write("</div>\n")  # section

        # ── Correlation Chains Section ─────────────────────────────────────
        if chains:
            f.write("<div class='section'>\n")
            crit = sum(1 for c in chains if c["severity"] == "critical")
            high = sum(1 for c in chains if c["severity"] == "high")
            f.write(f"<h2>&#128683; Attack Chain Correlation "
                    f"<span style='color:#8b949e;font-size:0.85em;font-weight:normal'>"
                    f"({len(chains)} detected — {crit} critical, {high} high)</span></h2>\n")
            for chain in chains[:50]:  # cap at 50 in HTML
                sev    = chain["severity"]
                comps  = ", ".join(chain["computers"]) or "?"
                users  = ", ".join(chain["users"]) or "?"
                f.write(f"<div class='chain sev-{sev}'>\n")
                f.write(f"<div class='chain-title'>{_esc(chain['rule_name'])}"
                        f"<span class='sev-badge {sev}'>{sev.upper()}</span></div>\n")
                f.write(f"<div class='chain-meta'>"
                        f"Tactic: {_esc(chain['tactic'])} | "
                        f"Time: {_fmt_ts(chain['first_ts'])} &rarr; {_fmt_ts(chain['last_ts'])} | "
                        f"Events: {chain['event_count']} | "
                        f"Computers: {_esc(comps)} | Users: {_esc(users)}"
                        f"</div>\n")
                f.write(f"<div class='chain-desc'>{_esc(chain['description'])}</div>\n")
                f.write("</div>\n")
            if len(chains) > 50:
                f.write(f"<div class='meta'>... and {len(chains)-50} more chains. "
                        f"Use --output report.pdf for full listing.</div>\n")
            f.write("</div>\n")

        # ── IOC Section ───────────────────────────────────────────────────
        if iocs and ioc_count > 0:
            f.write("<div class='section' id='ioc-section'>\n")
            f.write(f"<h2>&#127756; IOC Summary "
                    f"<span style='color:#8b949e;font-size:0.85em;font-weight:normal'>"
                    f"({ioc_count} total indicators)</span></h2>\n")

            # Tab bar for all IOC types (new model: list[IOCEntry])
            _ioc_tab_order = [
                ("ipv4",         "IPv4"),
                ("ipv6",         "IPv6"),
                ("domains",      "Domains"),
                ("urls",         "URLs"),
                ("sha256",       "SHA256"),
                ("sha1",         "SHA1"),
                ("md5",          "MD5"),
                ("processes",    "Processes"),
                ("commandlines", "Commands"),
                ("registry",     "Registry"),
                ("filepaths",    "Paths"),
                ("services",     "Services"),
                ("tasks",        "Tasks"),
                ("named_pipes",  "Pipes"),
                ("shares",       "Shares"),
                ("dlls",         "DLLs"),
                ("users",        "Users"),
                ("computers",    "Computers"),
            ]
            visible_tabs = [(k, lbl) for k, lbl in _ioc_tab_order if iocs.get(k)]
            if visible_tabs:
                f.write("<div class='tab-bar'>\n")
                for idx, (key, lbl) in enumerate(visible_tabs):
                    active = " active" if idx == 0 else ""
                    cnt    = len(iocs.get(key, []))
                    f.write(f"<button class='tab-btn{active}' "
                            f"onclick=\"switchTab('ioc-section','ioc-tab-{key}',this)\">"
                            f"{lbl} ({cnt})</button>\n")
                f.write("</div>\n")

                for idx, (key, lbl) in enumerate(visible_tabs):
                    active  = " active" if idx == 0 else ""
                    entries = iocs.get(key, [])
                    f.write(f"<div class='tab-content{active}' id='ioc-tab-{key}'>\n")

                    # Column header for context-rich entries
                    f.write(
                        "<div style='display:grid;grid-template-columns:1fr 60px 120px 120px 55px;"
                        "gap:4px;padding:4px 6px;color:#8b949e;font-size:0.78em;"
                        "border-bottom:1px solid #30363d;margin-bottom:4px'>"
                        "<span>Value</span><span style='text-align:center'>Count</span>"
                        "<span>First Seen</span><span>Last Seen</span>"
                        "<span style='text-align:center'>Score</span></div>\n"
                    )

                    for entry in entries[:200]:
                        if isinstance(entry, dict):
                            val   = entry.get("value", "")
                            cnt   = entry.get("count", 1)
                            first = (entry.get("first_seen") or "")[:16]
                            last  = (entry.get("last_seen")  or "")[:16]
                            score = entry.get("score", 0)
                            ti    = entry.get("threat_intel")
                        else:
                            val, cnt, first, last, score, ti = str(entry), 1, "", "", 0, None

                        # Score color
                        if score >= 61:
                            sc = "#e74c3c"
                        elif score >= 31:
                            sc = "#e67e22"
                        else:
                            sc = "#3fb950"

                        # Threat intel badge
                        ti_badge = ""
                        if ti:
                            verdict = ti.get("verdict", "")
                            link    = ti.get("permalink", "")
                            if verdict in ("malicious", "suspicious"):
                                ti_color = "#e74c3c"
                                ti_label = f"⚠ {verdict}"
                            elif verdict == "clean":
                                ti_color = "#3fb950"
                                ti_label = "✓ clean"
                            else:
                                ti_color = "#8b949e"
                                ti_label = verdict or "?"
                            if link:
                                ti_badge = (f"<a href='{_esc(link)}' style='color:{ti_color};"
                                            f"font-size:0.75em;margin-left:6px'>{ti_label}</a>")
                            else:
                                ti_badge = (f"<span style='color:{ti_color};"
                                            f"font-size:0.75em;margin-left:6px'>{ti_label}</span>")

                        f.write(
                            f"<div class='ioc-item' style='display:grid;"
                            f"grid-template-columns:1fr 60px 120px 120px 55px;gap:4px'>"
                            f"<span style='overflow:hidden;text-overflow:ellipsis;white-space:nowrap' "
                            f"title='{_esc(val[:500])}'>{_esc(val[:120])}{ti_badge}</span>"
                            f"<span style='text-align:center;color:#8b949e'>{cnt}</span>"
                            f"<span style='color:#8b949e;font-size:0.82em'>{_esc(first)}</span>"
                            f"<span style='color:#8b949e;font-size:0.82em'>{_esc(last)}</span>"
                            f"<span style='text-align:center;color:{sc};font-weight:bold'>"
                            f"{score}</span>"
                            f"</div>\n"
                        )

                    if len(entries) > 200:
                        f.write(f"<div class='meta' style='margin-top:6px'>"
                                f"... and {len(entries)-200} more. Export to CSV/STIX for full list.</div>\n")
                    f.write("</div>\n")
            f.write("</div>\n")

        # ── Event Table ───────────────────────────────────────────────────
        f.write("<div class='section'>\n")
        f.write(f"<h2>&#128203; Events ({len(events):,})</h2>\n")
        f.write(
            "<input type='text' id='searchInput' class='search-bar' "
            "placeholder='&#128269; Filter events... (searches all columns)'>"
            "<span id='searchCounter' class='search-counter'></span>"
            "<span id='wasmBadge' class='wasm-badge' title='WASM search active'>WASM&#9889;</span>"
            "\n"
        )

        # ── Filter toolbar ─────────────────────────────────────────────
        levels_set   = sorted(set(ev.get('level_name', 'Information') for ev in events))
        channels_set = sorted(set((ev.get('channel', '') or '')[:40] for ev in events if ev.get('channel')))
        comps_set    = sorted(set((ev.get('computer', '') or '')[:30] for ev in events if ev.get('computer')))
        eids_set     = sorted(set(str(ev.get('event_id', '')) for ev in events))

        # Row 1: dropdown filters
        f.write("<div class='filter-toolbar'>\n")
        f.write("<label>Filter:</label>\n")

        def _sel(el_id: str, label: str, opts: list[str], js: str) -> None:
            f.write(f"<select class='col-filter-select' id='{el_id}' onchange='{js}'>\n")
            f.write(f"<option value=''>{label}</option>\n")
            for o in opts:
                f.write(f"<option value='{_esc(o)}'>{_esc(o)}</option>\n")
            f.write("</select>\n")

        _sel("filterLevel",    "All Levels",    levels_set,        "_F.level=this.value;applyFilters()")
        _sel("filterChannel",  "All Channels",  channels_set[:80], "_F.channel=this.value;applyFilters()")
        _sel("filterComputer", "All Computers", comps_set[:50],    "_F.computer=this.value;applyFilters()")
        _sel("filterEventID",  "All Event IDs", eids_set[:200],    "_F.eid=this.value;applyFilters()")
        if all_tactics:
            _sel("filterTactic", "All Tactics", all_tactics,       "_F.tactic=this.value;applyFilters()")
        f.write("</div>\n")

        # Row 2: toggle buttons + time range + reset
        f.write("<div class='filter-toolbar'>\n")
        f.write("<button id='toggleSusp' class='filter-toggle' "
                "onclick=\"toggleFilter('suspOnly',this,'on-susp')\">&#9888; Suspicious</button>\n")
        f.write("<button id='toggleAttck' class='filter-toggle' "
                "onclick=\"toggleFilter('hasAttck',this,'on-atk')\">&#127919; Has ATT&amp;CK</button>\n")
        f.write("<button id='togglePS' class='filter-toggle' "
                "onclick=\"toggleFilter('hasPS',this,'on-ps')\">PS: Has Analysis</button>\n")
        f.write("<span style='flex:1'></span>\n")
        f.write("<label>From:</label>\n"
                "<input type='datetime-local' id='timeFrom' class='time-input' "
                "onchange=\"_F.timeFrom=this.value;applyFilters()\">\n")
        f.write("<label>To:</label>\n"
                "<input type='datetime-local' id='timeTo' class='time-input' "
                "onchange=\"_F.timeTo=this.value;applyFilters()\">\n")
        f.write("<button class='filter-reset' onclick='resetFilters()'>&#10006; Reset</button>\n")
        f.write("<span id='activeFilterBadge' class='active-filter-badge' style='display:none'></span>\n")
        f.write("</div>\n")

        # Search hint for field-specific syntax
        f.write("<div class='search-hint'>Tip: use field-specific search: "
                "<code>eid:4624</code> &nbsp;"
                "<code>level:error</code> &nbsp;"
                "<code>computer:srv01</code> &nbsp;"
                "<code>tactic:execution</code> &nbsp;"
                "<code>tid:T1059</code> &nbsp;— combine freely with free text</div>\n")

        f.write("<table>\n<thead><tr>")
        col_headers = [
            ("#", False), ("Timestamp", True), ("EventID", True), ("Level", True),
            ("Channel", True), ("Computer", True), ("Source", True),
            ("ATT&amp;CK", True), ("&nbsp;", False),
        ]
        for ci, (col, sortable) in enumerate(col_headers):
            if sortable:
                f.write(f"<th onclick='sortTable({ci})'>{col}"
                        f"<span class='sort-arrow'>\u2195</span></th>")
            else:
                f.write(f"<th class='no-sort'>{col}</th>")
        f.write("</tr></thead>\n<tbody>\n")

        for i, ev in enumerate(events):
            eid       = ev.get("event_id", 0)
            is_susp   = eid in SUSPICIOUS_EVENT_IDS
            lvl_name  = ev.get("level_name", "Information")
            badge_cls = LEVEL_BADGE_CLASS.get(lvl_name, "badge-info")
            attack_tags = ev.get("attack_tags") or []

            row_class = "event-row"
            if is_susp:
                row_class += " suspicious"

            ts     = _fmt_ts(ev.get("timestamp", ""))
            raw_ts = (ev.get("timestamp", "") or "").replace("Z", "").replace(" UTC", "")[:19]

            # Data attributes for filtering/sorting
            tactics_str = ";".join(dict.fromkeys(
                t.get("tactic", "") for t in attack_tags if t.get("tactic")))
            tids_str    = ";".join(t.get("tid", "") for t in attack_tags if t.get("tid"))

            # ATT&CK badges (max 3, one per tactic)
            atk_html = ""
            seen_tactics: set[str] = set()
            for tag in attack_tags[:3]:
                tactic = tag.get("tactic", "")
                if tactic in seen_tactics:
                    continue
                seen_tactics.add(tactic)
                color    = TACTIC_COLORS.get(tactic, "#555")
                tag_tid  = tag.get("tid", "")
                tag_name = tag.get("name", "")
                atk_html += (
                    f"<span class='atk-badge' style='background:{color}' "
                    f"title='{_esc(tag_tid)}: {_esc(tag_name)}'>"
                    f"{_esc(tag_tid)}</span>"
                )

            f.write(
                f"<tr class='{row_class}' data-idx='{i}'"
                f" data-ts='{_esc(raw_ts)}'"
                f" data-level='{_esc(lvl_name)}'"
                f" data-channel='{_esc((ev.get('channel','') or '')[:40])}'"
                f" data-computer='{_esc((ev.get('computer','') or '')[:30])}'"
                f" data-eid='{_esc(str(eid))}'"
                f" data-susp='{'1' if is_susp else '0'}'"
                f" data-has-atk='{'1' if attack_tags else '0'}'"
                f" data-atk-count='{len(attack_tags)}'"
                f" data-tactics='{_esc(tactics_str)}'"
                f" data-tids='{_esc(tids_str)}'"
                f" onclick='toggleDetail({i})'>\n"
            )
            f.write(f"  <td style='color:#484f58;font-size:0.8em'>{i+1}</td>\n")
            f.write(f"  <td class='ts'>{_esc(ts)}</td>\n")
            f.write(f"  <td class='event-id'>{_esc(eid)}</td>\n")
            f.write(f"  <td><span class='badge {badge_cls}'>{_esc(lvl_name)}</span></td>\n")
            f.write(f"  <td style='color:#8b949e;font-size:0.8em'>{_esc((ev.get('channel','') or '')[:25])}</td>\n")
            f.write(f"  <td style='font-size:0.82em'>{_esc((ev.get('computer','') or '')[:20])}</td>\n")
            f.write(f"  <td style='color:#8b949e;font-size:0.78em'>"
                    f"{_esc(os.path.basename(ev.get('source_file','') or '')[:22])}</td>\n")
            f.write(f"  <td>{atk_html}</td>\n")
            f.write(f"  <td><button class='expand-btn' title='Expand'>&#9654;</button></td>\n")
            f.write("</tr>\n")

            # Detail row — include ALL event fields
            detail_parts = []

            # Section 0: Human-readable description (from event_descriptions.py)
            if _get_desc is not None:
                try:
                    _desc = _get_desc(ev)
                except Exception:
                    _desc = None
                if _desc:
                    detail_parts.append(
                        f"<div class='desc-box-title'>&#128712; DESCRIPTION</div>"
                        f"<div class='desc-box'>{_esc(_desc)}</div>"
                    )

            # Section 1: Core Event Properties
            detail_parts.append("<div class='detail-section'>")
            detail_parts.append("<div class='detail-section-title'>\u2139\ufe0f Event Properties</div>")
            core_fields = [
                ("Event ID",    str(ev.get('event_id', ''))),
                ("Timestamp",   ev.get('timestamp', '')),
                ("Level",       ev.get('level_name', '')),
                ("Channel",     ev.get('channel', '')),
                ("Provider",    ev.get('provider', '')),
                ("Computer",    ev.get('computer', '')),
                ("User / SID",  ev.get('user_id', '')),
                ("Record ID",   str(ev.get('record_id', ''))),
                ("Activity ID", ev.get('activity_id', '')),
                ("Opcode",      ev.get('opcode', '')),
                ("Keywords",    ev.get('keywords', '')),
                ("Source File", ev.get('source_file', '')),
            ]
            for label, val in core_fields:
                if val:
                    detail_parts.append(
                        f"<span class='detail-key'>{_esc(label)}:</span> "
                        f"<span class='detail-val'>{_esc(str(val))}</span><br>")
            detail_parts.append("</div>")

            # Section 2: Event Data (payload)
            ed = ev.get("event_data", {}) or {}
            if ed:
                detail_parts.append("<div class='detail-section'>")
                detail_parts.append("<div class='detail-section-title'>\U0001f4cb Event Data</div>")
                for k, v in ed.items():
                    if v is not None:
                        val_str = str(v)
                        detail_parts.append(
                            f"<span class='detail-key'>{_esc(k)}:</span> "
                            f"<span class='detail-val'>{_esc(val_str[:2000])}</span><br>")
                detail_parts.append("</div>")

            detail_html = "\n".join(detail_parts)

            # Full ATT&CK detail
            atk_detail = ""
            if attack_tags:
                atk_detail = "<div style='margin-top:6px;color:#7ecba1'><b>ATT&amp;CK:</b> "
                atk_detail += " | ".join(
                    f"{_esc(t['tid'])} {_esc(t['name'])} [{_esc(t['tactic'])}]"
                    for t in attack_tags
                )
                atk_detail += "</div>"

            f.write(f"<tr id='detail-{i}' class='detail-row' style='display:none'>\n")
            f.write(f"  <td colspan='9'>{detail_html}{atk_detail}</td>\n")
            f.write("</tr>\n")

        f.write("</tbody></table>\n")
        f.write("</div>\n")  # section

        # ── Inline pre-computed search index (Tier 2 JS fallback) ────────────
        # Python generates compact lowercase search strings once at export time.
        # This makes the JS search O(n × string.indexOf) instead of O(n × DOM),
        # which is ~3-5x faster even without WASM, and costs ~20-80 KB extra.
        #
        # Perf fix #6: stream-write per-event instead of building a full list
        # in memory. Halves peak memory for large exports.
        f.write("<script>window._SD=[")
        for si, ev in enumerate(events):
            if si > 0:
                f.write(",")
            f.write(fast_dumps(_build_search_string(ev)))
        f.write("];</script>\n")

        # ── Optional WASM init (Tier 1 — present only when pkg/ was built) ───
        wasm_b64, glue_js = _load_wasm_assets()
        if wasm_b64 and glue_js:
            f.write(_wasm_init_block(wasm_b64, glue_js))

        f.write(_HTML_SCRIPT)
        f.write("</body></html>\n")

    logger.info("HTML export: %d events -> %s", len(events), filepath)
    return len(events)


# ── PDF dispatch ───────────────────────────────────────────────────────────────

def export_pdf(
    events: list[dict],
    filepath: str,
    attack_summary: dict | None = None,
    iocs:           dict | None = None,
    chains:         list[dict] | None = None,
    **_,
) -> int:
    from .pdf_exporter import export_pdf as _pdf
    return _pdf(events, filepath,
                attack_summary=attack_summary, iocs=iocs,
                chains=chains)


# ── Dispatch ───────────────────────────────────────────────────────────────────

EXPORT_FORMATS = {
    "csv":  export_csv,
    "json": export_json,
    "xml":  export_xml,
    "html": export_html,
    "pdf":  export_pdf,
}


def export(
    events:         list[dict],
    filepath:       str,
    fmt:            str | None        = None,
    attack_summary: dict | None       = None,
    iocs:           dict | None       = None,
    chains:         list[dict] | None = None,
) -> int:
    """
    Export events to file. Format inferred from extension if fmt not specified.
    Extra kwargs (attack_summary, iocs, chains) are passed to HTML/PDF exporters.
    """
    if fmt is None:
        ext = Path(filepath).suffix.lstrip(".").lower()
        fmt = ext if ext in EXPORT_FORMATS else "json"
    fmt = fmt.lower()
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"Unknown format '{fmt}'. Supported: {', '.join(EXPORT_FORMATS)}")

    fn = EXPORT_FORMATS[fmt]
    # Only pass extra kwargs to exporters that accept them (HTML + PDF)
    if fmt in ("html", "pdf"):
        return fn(events, filepath,
                  attack_summary=attack_summary, iocs=iocs,
                  chains=chains)
    return fn(events, filepath)
