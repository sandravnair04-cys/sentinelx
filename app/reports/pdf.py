"""Professional, downloadable PDF incident reports (ReportLab)."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..config import BASE_DIR

REPORT_DIR = BASE_DIR / "data" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

NAVY = colors.HexColor("#070d1b")
BLUE = colors.HexColor("#00b4ff")
GREY = colors.HexColor("#94a3b8")


def _styles():
    base = getSampleStyleSheet()
    base.add(
        ParagraphStyle(
            "SentinelTitle", parent=base["Title"], fontSize=26, leading=30,
            textColor=BLUE, alignment=TA_LEFT, spaceAfter=4,
        )
    )
    base.add(
        ParagraphStyle(
            "SentinelSub", parent=base["Normal"], fontSize=10, leading=14,
            textColor=GREY, spaceAfter=10,
        )
    )
    base.add(
        ParagraphStyle(
            "SentinelH2", parent=base["Heading2"], fontSize=13, leading=16,
            textColor=BLUE, spaceBefore=10, spaceAfter=5,
        )
    )
    base.add(
        ParagraphStyle(
            "SentinelBody", parent=base["BodyText"], fontSize=9, leading=12,
            textColor=colors.HexColor("#1e293b"), spaceAfter=4,
        )
    )
    base.add(
        ParagraphStyle(
            "SentinelCell", parent=base["BodyText"], fontSize=7.5, leading=9.5,
            spaceAfter=0,
        )
    )
    return base


def _table(data: list[list[Any]], widths: list[float]) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def generate_report(incident: Any, state: dict[str, Any] | None = None) -> Path:
    """Generate a PDF for an incident. Returns the path to the created file."""
    state = state or {}
    styles = _styles()
    safe_incident_id = str(incident.incident_id).replace("/", "_").replace("\\", "_")
    file_name = f"SENTINELX-{safe_incident_id}.pdf"
    path = REPORT_DIR / file_name
    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"SENTINELX Incident Report {incident.incident_id}", author="SENTINELX",
    )
    story: list[Any] = []
    story.append(Paragraph("SENTINELX", styles["SentinelTitle"]))
    story.append(Paragraph("Agentic AI Security Operations Center &mdash; Incident Report", styles["SentinelSub"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BLUE))
    story.append(Spacer(1, 8))

    simulation = bool(getattr(incident, "simulation", False))
    classification = "SIMULATED LAB DATA" if simulation else "INTERNAL / SECURITY SENSITIVE"
    story.append(
        _table(
            [
                ["Field", "Value"],
                ["Incident ID", escape(str(incident.incident_id))],
                ["Title", escape(str(incident.title))],
                ["Threat category", escape(str(incident.category))],
                ["Severity", escape(str(incident.severity))],
                ["Risk score", f"{incident.risk_score:.1f} / 100"],
                ["Status", escape(str(incident.status))],
                ["Detection time (UTC)", escape(str(incident.detection_time))],
                ["Source IP", escape(str(incident.source_ip or "n/a"))],
                ["Affected account", escape(str(incident.username or "n/a"))],
                ["Affected host", escape(str(incident.host or "n/a"))],
                ["Classification", classification],
            ],
            [45 * mm, 129 * mm],
        )
    )
    story.append(Spacer(1, 6))

    story.append(Paragraph("Executive Summary", styles["SentinelH2"]))
    summary = state.get("report", {}).get("executive_summary") or state.get("report", {}).get("summary") or incident.finding_summary
    story.append(Paragraph(escape(str(summary or "No investigation summary available.")), styles["SentinelBody"]))

    story.append(Paragraph("Investigation Timeline (UTC)", styles["SentinelH2"]))
    timeline = incident.timeline or []
    if timeline:
        rows = [["Timestamp", "Event / Code", "Account", "Source IP", "Description"]]
        for entry in timeline[:40]:
            rows.append(
                [
                    escape(str(entry.get("timestamp", "")))[:19],
                    escape(str(entry.get("code", entry.get("action", "")))),
                    escape(str(entry.get("username") or "-")),
                    escape(str(entry.get("source_ip") or "-")),
                    escape(str(entry.get("description", "")))[:100],
                ]
            )
        story.append(_table(rows, [30 * mm, 25 * mm, 25 * mm, 26 * mm, 68 * mm]))
    else:
        story.append(Paragraph("No timeline events recorded.", styles["SentinelBody"]))

    story.append(PageBreak())
    story.append(Paragraph("Evidence References and Hashes", styles["SentinelH2"]))
    evidence_rows = [["Type", "Description", "Reference", "SHA-256"]]
    for item in (state.get("evidence", []) or [])[:40]:
        evidence_rows.append(
            [
                escape(str(item.get("type", ""))),
                escape(str(item.get("description", "")))[:90],
                escape(str(item.get("event_uid", "")))[:24],
                escape(str(item.get("hash", item.get("hash_sha256", ""))))[:32],
            ]
        )
    if len(evidence_rows) == 1:
        evidence_rows.append(["-", "No evidence records", "-", "-"])
    story.append(_table(evidence_rows, [22 * mm, 60 * mm, 42 * mm, 50 * mm]))

    story.append(Paragraph("AI Agent Findings", styles["SentinelH2"]))
    agent_labels = [
        ("log_analysis", "Log Analysis Agent"),
        ("detection_analysis", "Threat Detection Agent"),
        ("investigation_findings", "Investigation Agent"),
        ("risk_assessment", "Risk Assessment Agent"),
        ("detection_analysis_note", "Incident Response Agent"),
        ("report", "Report Generation Agent"),
    ]
    for key, label in agent_labels:
        value = state.get(key)
        if not value:
            continue
        text = value.get("summary") or value.get("explanation") or value.get("narrative") or value
        story.append(Paragraph(f"<b>{escape(label)}:</b> {escape(str(text))[:1200]}", styles["SentinelBody"]))

    story.append(Paragraph("Risk Factors", styles["SentinelH2"]))
    factors = (state.get("risk_assessment", {}).get("factors") or [])
    if factors:
        for factor in factors:
            story.append(
                Paragraph(
                    f"&bull; {escape(str(factor.get('factor', '')))}: +{factor.get('points', 0)} "
                    f"&mdash; {escape(str(factor.get('reason', '')))}",
                    styles["SentinelBody"],
                )
            )
    else:
        story.append(Paragraph("No risk factors recorded.", styles["SentinelBody"]))

    story.append(Paragraph("Recommended Remediation", styles["SentinelH2"]))
    recommendations = (state.get("report", {}).get("remediation") or []) or (state.get("risk_assessment", {}).get("recommendations") or [])
    for rec in recommendations[:15]:
        story.append(Paragraph(f"&bull; {escape(str(rec))}", styles["SentinelBody"]))
    if not recommendations:
        story.append(Paragraph("No remediation recommendations recorded.", styles["SentinelBody"]))

    story.append(Paragraph("Analyst Approval History", styles["SentinelH2"]))
    approvals = state.get("approvals", [])
    if approvals:
        approval_rows = [["Action", "Decision", "Analyst", "Role", "Reason", "Time (UTC)"]]
        for approval in approvals[:20]:
            approval_rows.append(
                [
                    escape(str(approval.get("title", approval.get("action_type", ""))))[:60],
                    escape(str(approval.get("decision", ""))),
                    escape(str(approval.get("analyst", ""))),
                    escape(str(approval.get("analyst_role", ""))),
                    escape(str(approval.get("reason", "")))[:60],
                    escape(str(approval.get("time", "")))[:19],
                ]
            )
        story.append(_table(approval_rows, [40 * mm, 20 * mm, 25 * mm, 18 * mm, 45 * mm, 26 * mm]))
    else:
        story.append(Paragraph("No approval decisions recorded for this incident.", styles["SentinelBody"]))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.7, color=GREY))
    story.append(
        Paragraph(
            f"Generated by SENTINELX Report Generation Agent at {datetime.utcnow().isoformat()}Z. "
            "Agentic findings are decision support only; all conclusions are grounded in collected "
            "log evidence and deterministic detection results.",
            styles["SentinelSub"],
        )
    )
    doc.build(story)
    return path
