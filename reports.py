from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def generate_pdf(scan_data):
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=35,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("FixProof X Security Report", styles["Title"]))
    content.append(Spacer(1, 20))

    content.append(Paragraph(
        "<b>Website:</b> " + escape(str(scan_data.get("url", "N/A"))),
        styles["Normal"]
    ))
    content.append(Paragraph(
        "<b>Security Score:</b> " + escape(str(scan_data.get("score", 0))) + "/100",
        styles["Normal"]
    ))
    content.append(Paragraph(
        "<b>Risk Level:</b> " + escape(str(scan_data.get("risk_level", "N/A"))),
        styles["Normal"]
    ))

    content.append(Spacer(1, 20))
    content.append(Paragraph("Security Check Results", styles["Heading2"]))
    content.append(Spacer(1, 10))

    rows = [["Security Check", "Status", "Details"]]

    for item in scan_data.get("results", []):
        rows.append([
            Paragraph(escape(str(item.get("name", "N/A"))), styles["Normal"]),
            Paragraph(escape(str(item.get("status", "N/A"))), styles["Normal"]),
            Paragraph(escape(str(item.get("details", "N/A"))), styles["Normal"])
        ])

    table = Table(
        rows,
        colWidths=[1.5 * inch, 1.0 * inch, 3.8 * inch],
        repeatRows=1
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172554")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")])
    ]))

    content.append(table)
    content.append(Spacer(1, 20))
    content.append(Paragraph("Recommendations", styles["Heading2"]))

    recommendations = {
        "HTTPS Encryption": "Use HTTPS to protect website communication.",
        "Content Security Policy": "Configure a suitable CSP header.",
        "Clickjacking Protection": "Configure X-Frame-Options or CSP frame-ancestors.",
        "HSTS Security": "Configure Strict-Transport-Security.",
        "MIME Sniffing Protection": "Set X-Content-Type-Options to nosniff."
    }

    for item in scan_data.get("results", []):
        if item.get("status") != "Passed":
            advice = recommendations.get(
                item.get("name"),
                "Review this security configuration."
            )
            content.append(Paragraph("- " + escape(advice), styles["Normal"]))
            content.append(Spacer(1, 5))

    content.append(Spacer(1, 20))
    content.append(Paragraph(
        "Disclaimer: This report checks selected HTTP security headers only. "
        "It is not a complete security audit. Scan only websites you own "
        "or are authorized to test.",
        styles["Italic"]
    ))

    doc.build(content)
    buffer.seek(0)
    return buffer
