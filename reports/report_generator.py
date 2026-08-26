"""
reports/report_generator.py
Generates downloadable incident reports (PRD section 6 "Reports"):
columns are Date, Attack Type, Severity, AI Summary, Recommendation.
Export formats: PDF and CSV.
"""

import csv
import io
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#8b0000"),
    "High": colors.HexColor("#d9534f"),
    "Medium": colors.HexColor("#f0ad4e"),
    "Low": colors.HexColor("#5cb85c"),
}


def _incident_rows(incidents):
    rows = []
    for inc in incidents:
        recommendation = inc.get("recommendation") or ""
        if isinstance(recommendation, list):
            recommendation = "; ".join(recommendation)
        rows.append({
            "date": (inc.get("created_at") or "")[:19],
            "attack_type": inc.get("attack_type") or "",
            "severity": inc.get("severity") or "",
            "summary": inc.get("ai_summary") or "",
            "recommendation": recommendation,
        })
    return rows


def generate_csv(incidents, output_path):
    rows = _incident_rows(incidents)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["date", "attack_type", "severity", "summary", "recommendation"]
        )
        writer.writerow({
            "date": "Date", "attack_type": "Attack Type", "severity": "Severity",
            "summary": "AI Summary", "recommendation": "Recommendation",
        })
        writer.writerows(rows)
    return output_path


def generate_pdf(incidents, output_path):
    rows = _incident_rows(incidents)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=landscape(letter),
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
    )
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle("cell", parent=styles["Normal"], fontSize=8, leading=10)
    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=18)

    story = [
        Paragraph("AI-Enhanced SIEM &mdash; Incident Report", title_style),
        Spacer(1, 4),
        Paragraph(f"Total incidents: {len(rows)}", styles["Normal"]),
        Spacer(1, 12),
    ]

    table_data = [["Date", "Attack Type", "Severity", "AI Summary", "Recommendation"]]
    for r in rows:
        table_data.append([
            Paragraph(r["date"], cell_style),
            Paragraph(r["attack_type"], cell_style),
            Paragraph(r["severity"], cell_style),
            Paragraph(r["summary"], cell_style),
            Paragraph(r["recommendation"], cell_style),
        ])

    table = Table(
        table_data,
        colWidths=[1.2 * inch, 1.6 * inch, 0.8 * inch, 3.2 * inch, 3.2 * inch],
        repeatRows=1,
    )

    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f6f8")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]

    for i, r in enumerate(rows, start=1):
        color = SEVERITY_COLORS.get(r["severity"])
        if color:
            style_commands.append(("TEXTCOLOR", (2, i), (2, i), color))
            style_commands.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))

    table.setStyle(TableStyle(style_commands))
    story.append(table)
    doc.build(story)
    return output_path
