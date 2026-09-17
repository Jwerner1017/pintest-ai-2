"""PDF report generation using ReportLab."""
from io import BytesIO
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#CA8A04"),
    "low": colors.HexColor("#16A34A"),
    "info": colors.HexColor("#2563EB"),
}


def build_pdf(report: dict, scans: list[dict]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=report.get("title", "PentestAI Report"),
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleRed", parent=styles["Title"],
        textColor=colors.HexColor("#DC2626"), fontSize=22, spaceAfter=12,
    )
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#1F2937"), spaceBefore=12)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9, textColor=colors.grey)

    story = []
    story.append(Paragraph("PentestAI Security Assessment", title_style))
    story.append(Paragraph(report.get("title", ""), styles["Heading3"]))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &nbsp;·&nbsp; Report ID: {report.get('id', 'n/a')}",
        small,
    ))
    story.append(Spacer(1, 0.25 * inch))

    # Executive summary table
    summary = report.get("summary", {}) or {}
    story.append(Paragraph("Executive Summary", h2))
    summary_data = [
        ["Severity", "Count"],
        ["Critical", summary.get("critical", 0)],
        ["High", summary.get("high", 0)],
        ["Medium", summary.get("medium", 0)],
        ["Low", summary.get("low", 0)],
        ["Total", summary.get("total_vulnerabilities", 0)],
    ]
    t = Table(summary_data, colWidths=[2.5 * inch, 1.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.25 * inch))

    # Per-scan details
    for scan in scans:
        story.append(PageBreak())
        story.append(Paragraph(f"Scan: {scan.get('scan_type', 'unknown').upper()} — {scan.get('target', '')}", h2))
        story.append(Paragraph(
            f"Created: {scan.get('created_at', '')} &nbsp;·&nbsp; Engine: {scan.get('results', {}).get('scan_engine', 'n/a')}",
            small,
        ))
        story.append(Spacer(1, 0.1 * inch))

        results = scan.get("results", {}) or {}
        ports = results.get("ports") or []
        if ports:
            story.append(Paragraph("Open Ports & Services", styles["Heading3"]))
            port_rows = [["Port", "Proto", "Service", "State", "Version"]]
            for p in ports[:50]:
                port_rows.append([
                    str(p.get("port", "")),
                    p.get("protocol", "tcp"),
                    p.get("service", ""),
                    p.get("state", ""),
                    p.get("version", ""),
                ])
            pt = Table(port_rows, colWidths=[0.6 * inch, 0.7 * inch, 1.2 * inch, 0.9 * inch, 2.6 * inch])
            pt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]))
            story.append(pt)
            story.append(Spacer(1, 0.15 * inch))

        vulns = results.get("vulnerabilities") or []
        if vulns:
            story.append(Paragraph("Vulnerabilities", styles["Heading3"]))
            for v in vulns:
                sev = (v.get("severity") or "info").lower()
                color = SEVERITY_COLORS.get(sev, colors.grey)
                sev_para = Paragraph(
                    f'<font color="{color.hexval()}"><b>{sev.upper()}</b></font> '
                    f'— <b>{v.get("id", "n/a")}</b>',
                    body,
                )
                story.append(sev_para)
                story.append(Paragraph(v.get("description", ""), body))
                if v.get("remediation"):
                    story.append(Paragraph(f"<i>Remediation:</i> {v['remediation']}", body))
                story.append(Spacer(1, 0.08 * inch))

        if not ports and not vulns:
            story.append(Paragraph("No structured results available.", body))

    doc.build(story)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes
