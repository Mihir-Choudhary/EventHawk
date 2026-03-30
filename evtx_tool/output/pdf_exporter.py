"""
PDF Report Exporter for EventHawk.

Requires: reportlab >= 4.0  (py -3 -m pip install reportlab)

Sections:
  1. Cover Page          — case name / analyst / date / tool version
  2. Executive Summary   — key stats (files, events, chains, iocs)
  3. ATT&CK Coverage     — tactic/technique table with hit counts
  4. Correlation Chains  — top 20 detected attack chains
  5. IOC Summary         — top IPs, users, hashes, commands
  6. Top Events          — first 500 events in a table
  7. Case Notes          — if case dict provided

Falls back to a helpful ImportError message if reportlab is not installed.
"""

from __future__ import annotations

import logging
import operator as _operator
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_BY_COUNT_DESC = _operator.itemgetter(1)  # key for sorted(..., reverse=True) on (item, count) pairs

# ── Colour palette ────────────────────────────────────────────────────────────

_C_DARK_BG    = (0.10, 0.10, 0.18)   # #1a1a2e
_C_HEADER     = (0.31, 0.76, 0.97)   # #4fc3f7
_C_TEXT       = (0.88, 0.88, 0.88)
_C_CRITICAL   = (0.72, 0.11, 0.11)
_C_HIGH       = (0.78, 0.32, 0.00)
_C_MEDIUM     = (0.55, 0.28, 0.00)
_C_LOW        = (0.09, 0.38, 0.50)
_C_WHITE      = (1, 1, 1)
_C_LIGHT_BG   = (0.96, 0.96, 0.98)
_C_ACCENT     = (0.06, 0.19, 0.38)   # #0f3460

_SEV_COLORS = {
    "critical": _C_CRITICAL,
    "high":     _C_HIGH,
    "medium":   _C_MEDIUM,
    "low":      _C_LOW,
}

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def export_pdf(
    events:      list[dict],
    filepath:    str,
    attack_summary: dict | None  = None,
    iocs:        dict | None     = None,
    chains:      list[dict] | None = None,
    title:       str             = "EventHawk — Analysis Report",
) -> int:
    """
    Generate a PDF report.

    Parameters
    ----------
    events         : matched event list (used for top-events table)
    filepath       : destination .pdf path
    attack_summary : output of build_attack_summary() or None
    iocs           : output of extract_iocs() or None
    chains         : output of correlate() or None
    title          : report title

    Returns number of events included.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )
        pass  # BUG 25 fix: removed unused KeepTogether import
    except ImportError:
        raise ImportError(
            "reportlab is required for PDF export.\n"
            "Install it with:  py -3 -m pip install reportlab"
        )

    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
        title=title,
        author="EventHawk",
    )

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    W, H   = A4

    def _style(name, **kw):
        s = ParagraphStyle(name, parent=normal, **kw)
        return s

    s_title   = _style("T", fontSize=26, textColor=colors.Color(*_C_HEADER),
                        leading=32, spaceAfter=6)
    s_sub     = _style("Sub", fontSize=13, textColor=colors.Color(*_C_TEXT),
                        leading=18, spaceAfter=4)
    s_meta    = _style("Meta", fontSize=9,  textColor=colors.Color(0.6,0.6,0.6),
                        leading=13, spaceAfter=2)
    s_h1      = _style("H1", fontSize=16, textColor=colors.Color(*_C_HEADER),
                        leading=22, spaceBefore=14, spaceAfter=6,
                        borderPadding=(0,0,4,0))
    s_h2      = _style("H2", fontSize=12, textColor=colors.Color(*_C_ACCENT),
                        leading=16, spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold")
    s_body    = _style("Body", fontSize=9, textColor=colors.Color(*_C_TEXT),
                        leading=13, spaceAfter=3)
    s_mono    = _style("Mono", fontSize=8, fontName="Courier",
                        textColor=colors.Color(0.7,0.9,0.7), leading=11)
    s_warn    = _style("Warn", fontSize=9, textColor=colors.Color(*_C_HIGH),
                        leading=13, spaceAfter=3)
    s_critical= _style("Crit", fontSize=9, textColor=colors.Color(*_C_CRITICAL),
                        leading=13, spaceAfter=3, fontName="Helvetica-Bold")

    rl_colors = colors  # alias for table styles

    story = []

    # ── Cover Page ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph(title, s_title))
    story.append(Paragraph("EventHawk — DFIR Analysis Report", s_sub))
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1,
                            color=rl_colors.Color(*_C_HEADER)))
    story.append(Spacer(1, 0.5*cm))

    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    meta_rows = [
        ("Generated",    generated),
        ("Total Events", f"{len(events):,}"),
        ("Chains Found", f"{len(chains):,}" if chains else "n/a (--correlate not used)"),
        # BUG 23 fix: use .get() with defaults to avoid KeyError if summary keys are missing
        ("IOCs Found",   (
            f"{iocs.get('summary',{}).get('ipv4',0) + iocs.get('summary',{}).get('sha256',0) + iocs.get('summary',{}).get('md5',0)} indicators"
            if iocs else "n/a (--ioc not used)"
        )),
    ]

    meta_table_data = [[Paragraph(k, s_meta), Paragraph(v, s_body)] for k, v in meta_rows]
    meta_table = Table(meta_table_data, colWidths=[4*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), rl_colors.Color(0.97,0.97,1.0)),
        ("TEXTCOLOR",   (0,0), (0,-1),  rl_colors.Color(0.4,0.4,0.5)),
        ("FONTNAME",    (0,0), (0,-1),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[rl_colors.white, rl_colors.Color(0.95,0.95,1.0)]),
        ("GRID",        (0,0), (-1,-1), 0.3, rl_colors.Color(0.8,0.8,0.85)),
        ("TOPPADDING",  (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(meta_table)
    story.append(PageBreak())

    # ── Executive Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", s_h1))
    story.append(HRFlowable(width="100%", thickness=0.5,
                            color=rl_colors.Color(*_C_HEADER)))
    story.append(Spacer(1, 0.3*cm))

    # Level breakdown
    by_level: dict[str, int] = {}
    by_eid:   dict[int, int] = {}
    by_comp:  dict[str, int] = {}
    for ev in events:
        lvl = ev.get("level_name", "Information")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        eid = ev.get("event_id", 0)
        by_eid[eid] = by_eid.get(eid, 0) + 1
        comp = ev.get("computer", "")
        if comp:
            by_comp[comp] = by_comp.get(comp, 0) + 1

    top_eids  = sorted(by_eid.items(),  key=_BY_COUNT_DESC, reverse=True)[:10]
    top_comps = sorted(by_comp.items(), key=_BY_COUNT_DESC, reverse=True)[:5]

    summary_text = (
        f"This report covers <b>{len(events):,} matched events</b> extracted from EVTX logs. "
    )
    if chains:
        _sev = Counter(c["severity"] for c in chains)
        crit = _sev["critical"]
        high = _sev["high"]
        summary_text += (
            f"The correlation engine detected <b>{len(chains)} attack chains</b>, "
            f"including {crit} critical and {high} high severity findings. "
        )
    story.append(Paragraph(summary_text, s_body))
    story.append(Spacer(1, 0.3*cm))

    # Level summary table
    level_data = [["Level", "Count"]]
    for lvl in ["Critical", "Error", "Warning", "Information", "Verbose"]:
        cnt = by_level.get(lvl, 0)
        if cnt:
            level_data.append([lvl, f"{cnt:,}"])
    lvl_table = Table(level_data, colWidths=[5*cm, 3*cm])
    lvl_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0),  rl_colors.Color(*_C_ACCENT)),
        ("TEXTCOLOR",   (0,0), (-1,0),  rl_colors.white),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.white, rl_colors.Color(0.95,0.95,1.0)]),
        ("GRID",        (0,0), (-1,-1), 0.3, rl_colors.Color(0.8,0.8,0.85)),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("ALIGN",       (1,0), (1,-1),  "RIGHT"),
    ]))
    story.append(lvl_table)
    story.append(Spacer(1, 0.4*cm))

    # Top event IDs
    story.append(Paragraph("Top Event IDs", s_h2))
    eid_data = [["Event ID", "Count"]] + [[str(e), f"{c:,}"] for e, c in top_eids]
    eid_table = Table(eid_data, colWidths=[5*cm, 3*cm])
    eid_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0),  rl_colors.Color(*_C_ACCENT)),
        ("TEXTCOLOR",   (0,0), (-1,0),  rl_colors.white),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.white, rl_colors.Color(0.95,0.95,1.0)]),
        ("GRID",        (0,0), (-1,-1), 0.3, rl_colors.Color(0.8,0.8,0.85)),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("ALIGN",       (1,0), (1,-1),  "RIGHT"),
    ]))
    story.append(eid_table)

    if top_comps:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("Most Active Computers", s_h2))
        comp_data = [["Computer", "Events"]] + [[c, f"{n:,}"] for c, n in top_comps]
        comp_table = Table(comp_data, colWidths=[9*cm, 3*cm])
        comp_table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  rl_colors.Color(*_C_ACCENT)),
            ("TEXTCOLOR",   (0,0), (-1,0),  rl_colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.white, rl_colors.Color(0.95,0.95,1.0)]),
            ("GRID",        (0,0), (-1,-1), 0.3, rl_colors.Color(0.8,0.8,0.85)),
            ("TOPPADDING",  (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("ALIGN",       (1,0), (1,-1),  "RIGHT"),
        ]))
        story.append(comp_table)

    story.append(PageBreak())

    # ── ATT&CK Coverage ────────────────────────────────────────────────────────
    if attack_summary and attack_summary.get("by_tactic"):
        story.append(Paragraph("MITRE ATT&CK Coverage", s_h1))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=rl_colors.Color(*_C_HEADER)))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            f"<b>{attack_summary['total_tagged']:,}</b> events mapped to ATT&CK techniques "
            f"across <b>{len(attack_summary['by_tactic'])}</b> tactics.",
            s_body
        ))
        story.append(Spacer(1, 0.3*cm))

        # Tactics table
        tactic_data = [["Tactic", "Events"]]
        for tactic in TACTIC_ORDER:
            cnt = attack_summary["by_tactic"].get(tactic, 0)
            if cnt:
                tactic_data.append([tactic, f"{cnt:,}"])

        tactic_table = Table(tactic_data, colWidths=[10*cm, 3*cm])
        tactic_table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  rl_colors.Color(*_C_ACCENT)),
            ("TEXTCOLOR",   (0,0), (-1,0),  rl_colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.white, rl_colors.Color(0.95,0.95,1.0)]),
            ("GRID",        (0,0), (-1,-1), 0.3, rl_colors.Color(0.8,0.8,0.85)),
            ("TOPPADDING",  (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("ALIGN",       (1,0), (1,-1),  "RIGHT"),
        ]))
        story.append(tactic_table)
        story.append(Spacer(1, 0.4*cm))

        # Techniques table (top 30 by count)
        by_tech = sorted(
            attack_summary["by_technique"].items(),
            key=lambda x: -x[1]["count"]
        )[:30]
        if by_tech:
            story.append(Paragraph("Top Techniques", s_h2))
            tech_data = [["Technique ID", "Name", "Tactic", "Events"]]
            for tid, info in by_tech:
                tech_data.append([tid, info["name"][:50], info["tactic"], f"{info['count']:,}"])
            tech_table = Table(tech_data, colWidths=[2.5*cm, 7*cm, 4*cm, 2*cm])
            tech_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,0),  rl_colors.Color(*_C_ACCENT)),
                ("TEXTCOLOR",   (0,0), (-1,0),  rl_colors.white),
                ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.white, rl_colors.Color(0.95,0.95,1.0)]),
                ("GRID",        (0,0), (-1,-1), 0.3, rl_colors.Color(0.8,0.8,0.85)),
                ("TOPPADDING",  (0,0), (-1,-1), 3),
                ("BOTTOMPADDING",(0,0),(-1,-1),3),
                ("LEFTPADDING", (0,0), (-1,-1), 6),
                ("ALIGN",       (3,0), (3,-1),  "RIGHT"),
            ]))
            story.append(tech_table)
        story.append(PageBreak())

    # ── Correlation Chains ─────────────────────────────────────────────────────
    if chains:
        story.append(Paragraph(f"Attack Chain Findings ({len(chains)} Detected)", s_h1))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=rl_colors.Color(*_C_HEADER)))
        story.append(Spacer(1, 0.3*cm))

        for i, chain in enumerate(chains[:20], 1):
            sev = chain["severity"]
            sev_color = rl_colors.Color(*_SEV_COLORS.get(sev, _C_LOW))
            computers = ", ".join(chain["computers"]) or "?"
            users     = ", ".join(chain["users"]) or "?"

            # BUG 24 fix: Table requires 2D list of rows×cols.
            # 4 paragraphs in 1 column = 4 rows, each with 1 cell.
            header_parts = [
                [Paragraph(f"{i}. {chain['rule_name']}", s_h2)],
                [Paragraph(
                    f"Severity: <b>{sev.upper()}</b>  |  "
                    f"Tactic: {chain['tactic']}  |  "
                    f"Events: {chain['event_count']}  |  "
                    f"Time: {_fmt_ts(chain['first_ts'])} - {_fmt_ts(chain['last_ts'])}",
                    s_meta
                )],
                [Paragraph(chain["description"], s_body)],
                [Paragraph(f"Affected: {computers}  |  Users: {users}", s_meta)],
            ]
            chain_table = Table(header_parts, colWidths=[17*cm])
            bg_color = rl_colors.Color(
                *{"critical": (0.3,0.05,0.05), "high": (0.3,0.15,0.02),
                  "medium": (0.15,0.1,0.0), "low": (0.05,0.1,0.2)}.get(sev, (0.05,0.1,0.2))
            )
            chain_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), bg_color),
                ("BOX",        (0,0), (-1,-1), 1, sev_color),
                ("TOPPADDING",  (0,0), (-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1),6),
                ("LEFTPADDING", (0,0), (-1,-1), 10),
                ("RIGHTPADDING",(0,0), (-1,-1), 10),
            ]))
            story.append(chain_table)
            story.append(Spacer(1, 0.2*cm))

        story.append(PageBreak())

    # ── IOC Summary ────────────────────────────────────────────────────────────
    if iocs:
        story.append(Paragraph("Indicators of Compromise (IOC Summary)", s_h1))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=rl_colors.Color(*_C_HEADER)))
        story.append(Spacer(1, 0.2*cm))

        ioc_sections = [
            ("IPv4 Addresses",   "ipv4",  20),
            ("SHA256 Hashes",    "sha256", 20),
            ("MD5 Hashes",       "md5",   20),
            ("Usernames",        "users", 30),
            ("Computers",        "computers", 20),
            ("Processes",        "processes", 20),
            ("Domains",          "domains", 20),
        ]
        for label, key, limit in ioc_sections:
            vals = iocs.get(key, [])
            if not vals:
                continue
            story.append(Paragraph(f"{label} ({len(vals)} total)", s_h2))
            ioc_data = [[Paragraph(str(v)[:80], s_mono)] for v in vals[:limit]]
            if len(vals) > limit:
                ioc_data.append([Paragraph(f"... and {len(vals)-limit} more", s_meta)])
            ioc_table = Table(ioc_data, colWidths=[17*cm])
            ioc_table.setStyle(TableStyle([
                ("ROWBACKGROUNDS", (0,0), (-1,-1), [rl_colors.Color(0.05,0.08,0.12),
                                                     rl_colors.Color(0.08,0.11,0.16)]),
                ("TOPPADDING",  (0,0), (-1,-1), 3),
                ("BOTTOMPADDING",(0,0),(-1,-1),3),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
            ]))
            story.append(ioc_table)
            story.append(Spacer(1, 0.2*cm))

        story.append(PageBreak())

    # ── Top Events Table ───────────────────────────────────────────────────────
    display_events = events[:500]
    story.append(Paragraph(
        f"Event Log (first {len(display_events):,} of {len(events):,} events)",
        s_h1
    ))
    story.append(HRFlowable(width="100%", thickness=0.5,
                            color=rl_colors.Color(*_C_HEADER)))
    story.append(Spacer(1, 0.2*cm))

    event_data = [["Timestamp", "EventID", "Level", "Computer", "Channel", "Source"]]
    for ev in display_events:
        ts      = _fmt_ts(ev.get("timestamp", ""))
        eid     = str(ev.get("event_id", ""))
        lvl     = ev.get("level_name", "")[:12]
        comp    = ev.get("computer", "")[:20]
        channel = ev.get("channel", "")[:22]
        src     = os.path.basename(ev.get("source_file", ""))[:20]
        event_data.append([ts, eid, lvl, comp, channel, src])

    ev_table = Table(event_data, colWidths=[3.5*cm, 1.5*cm, 2*cm, 3.5*cm, 3.5*cm, 2.5*cm])
    ev_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0),  rl_colors.Color(*_C_ACCENT)),
        ("TEXTCOLOR",   (0,0), (-1,0),  rl_colors.white),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0), (-1,-1), 7),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.white, rl_colors.Color(0.95,0.95,1.0)]),
        ("GRID",        (0,0), (-1,-1), 0.2, rl_colors.Color(0.85,0.85,0.88)),
        ("TOPPADDING",  (0,0), (-1,-1), 2),
        ("BOTTOMPADDING",(0,0),(-1,-1),2),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(ev_table)

    # ── Build PDF ─────────────────────────────────────────────────────────────
    doc.build(story)
    logger.info("PDF export: %d events -> %s", len(events), filepath)
    return len(events)


def _fmt_ts(ts: str) -> str:
    return ts.replace("T", " ").replace("Z", "")[:19] if ts else ""
