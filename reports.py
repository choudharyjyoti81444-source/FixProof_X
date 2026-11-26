from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from datetime import datetime


def safe_text(value):
    return escape(str(value if value is not None else "N/A"))


def generate_pdf(data):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#14213D"),
        alignment=TA_CENTER,
        spaceAfter=10
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0077B6"),
        spaceBefore=15,
        spaceAfter=8
    )

    elements = []

    elements.append(Paragraph("FIXPROOF X", title_style))
    elements.append(
        Paragraph("Website Security Configuration Report", styles["Normal"])
    )
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Scan Summary", heading_style))

    summary = [
        ["Website URL", safe_text(data.get("url"))],
        ["Risk Score", safe_text(data.get("score", 0)) + "/100"],
        ["Risk Level", safe_text(data.get("risk_level", "N/A"))],
        ["Generated On", datetime.now().strftime("%d-%m-%Y %H:%M")]
    ]

    summary_table = Table(summary, colWidths=[130, 350])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8F1F8")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#14213D")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(summary_table)

    # Risk Summary

    elements.append(Paragraph("Risk Summary", heading_style))

    risk_summary = data.get("risk_summary", {})

    risk_rows = [["Category", "Count"]]

    for key in [
        "Critical", "High", "Medium", "Low",
        "Passed", "Missing", "Failed", "Not Observed"
    ]:
        risk_rows.append([key, str(risk_summary.get(key, 0))])

    risk_table = Table(risk_rows, colWidths=[240, 100], repeatRows=1)

    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7)
    ]))

    elements.append(risk_table)

    # Technology Detection

    elements.append(Paragraph("Technology Detection", heading_style))

    technologies = data.get("technologies", [])

    tech_rows = [["Technology", "Category", "Confidence"]]

    if technologies:
        for tech in technologies:
            tech_rows.append([
                safe_text(tech.get("name")),
                safe_text(tech.get("category")),
                safe_text(tech.get("confidence"))
            ])
    else:
        tech_rows.append(["No indicators detected", "-", "-"])

    tech_table = Table(
        tech_rows,
        colWidths=[160, 160, 120],
        repeatRows=1
    )

    tech_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(tech_table)

    # Security Results

    elements.append(Paragraph("Security Check Results", heading_style))

    results = data.get("results", [])

    table_data = [["Security Check", "Status", "Details"]]

    for item in results:
        table_data.append([
            safe_text(item.get("name")),
            safe_text(item.get("status")),
            Paragraph(safe_text(item.get("details")), styles["BodyText"])
        ])

    results_table = Table(
        table_data,
        colWidths=[135, 75, 270],
        repeatRows=1
    )

    results_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#F2F6FA")
        ])
    ]))

    elements.append(results_table)

    elements.append(Spacer(1, 20))
    elements.append(Paragraph("Important Note", heading_style))

    elements.append(Paragraph(
        "This report checks selected HTTP security headers and possible "
        "technology indicators. Technology detection is based on response "
        "headers and is not confirmation of the underlying technology. "
        "This is not a complete vulnerability assessment or penetration test. "
        "Scan only websites you own or are authorized to assess.",
        styles["BodyText"]
    ))

    document.build(elements)
    buffer.seek(0)

    return buffer