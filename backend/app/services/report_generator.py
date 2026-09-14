"""
Report Generator — produces PDF and CSV reports from alert/anomaly data.
PDF styled to match the dashboard's dark SOC theme.
"""
import os
import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from app.config import settings


# Custom colors matching the SOC theme
BG_COLOR = colors.HexColor("#0D0D0D")
SURFACE_COLOR = colors.HexColor("#141414")
CARD_COLOR = colors.HexColor("#1A1A1A")
RED_ACCENT = colors.HexColor("#FF3B3B")
AMBER_ACCENT = colors.HexColor("#F59E0B")
GREEN_ACCENT = colors.HexColor("#22C55E")
TEXT_PRIMARY = colors.HexColor("#F5F5F5")
TEXT_SECONDARY = colors.HexColor("#888888")
BORDER_COLOR = colors.HexColor("#2A2A2A")


def generate_pdf_report(
    alerts: list,
    metrics: list = None,
    title: str = "NetShield AI — Threat Intelligence Report",
) -> str:
    """Generate a styled PDF report and return the file path."""
    reports_dir = Path(settings.REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"netshield_report_{timestamp}.pdf"
    filepath = reports_dir / filename

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=landscape(A4),
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Title'],
        fontSize=22, textColor=TEXT_PRIMARY, spaceAfter=10,
        alignment=TA_LEFT,
    )
    subtitle_style = ParagraphStyle(
        'CustomSubtitle', parent=styles['Normal'],
        fontSize=11, textColor=TEXT_SECONDARY, spaceAfter=20,
    )
    heading_style = ParagraphStyle(
        'CustomHeading', parent=styles['Heading2'],
        fontSize=14, textColor=RED_ACCENT, spaceAfter=10, spaceBefore=20,
    )
    normal_style = ParagraphStyle(
        'CustomNormal', parent=styles['Normal'],
        fontSize=9, textColor=TEXT_PRIMARY,
    )

    elements = []

    # Title
    elements.append(Paragraph(title, title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Classification: CONFIDENTIAL",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1, color=RED_ACCENT))
    elements.append(Spacer(1, 10))

    # Executive Summary
    if alerts:
        total = len(alerts)
        critical = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
        high = sum(1 for a in alerts if a.get('severity') == 'HIGH')
        medium = sum(1 for a in alerts if a.get('severity') == 'MEDIUM')
        low = sum(1 for a in alerts if a.get('severity') == 'LOW')

        elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        summary_data = [
            ["Total Alerts", str(total)],
            ["Critical", str(critical)],
            ["High", str(high)],
            ["Medium", str(medium)],
            ["Low", str(low)],
        ]
        summary_table = Table(summary_data, colWidths=[150, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), SURFACE_COLOR),
            ('TEXTCOLOR', (0, 0), (0, -1), TEXT_SECONDARY),
            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_PRIMARY),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

    # Model Metrics
    if metrics:
        elements.append(Paragraph("MODEL PERFORMANCE METRICS", heading_style))
        metric_header = ["Model", "Dataset", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"]
        metric_rows = [metric_header]
        for m in metrics:
            metric_rows.append([
                str(m.get('model_name', '')),
                str(m.get('dataset', '')),
                f"{m.get('accuracy', 0):.4f}",
                f"{m.get('precision_score', 0):.4f}",
                f"{m.get('recall', 0):.4f}",
                f"{m.get('f1_score', 0):.4f}",
                f"{m.get('roc_auc', 0):.4f}",
            ])
        
        metric_table = Table(metric_rows, colWidths=[120, 90, 70, 70, 70, 70, 70])
        metric_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), CARD_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), RED_ACCENT),
            ('BACKGROUND', (0, 1), (-1, -1), SURFACE_COLOR),
            ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_PRIMARY),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(metric_table)
        elements.append(Spacer(1, 15))

    # Alert Details Table
    if alerts:
        elements.append(Paragraph("ALERT DETAILS", heading_style))
        header = ["#", "Source IP", "Dest IP", "Protocol", "Attack Type", "Risk", "Severity", "Status"]
        table_data = [header]

        display_alerts = alerts[:100]  # Limit to 100 rows in PDF
        for i, a in enumerate(display_alerts, 1):
            table_data.append([
                str(i),
                str(a.get('source_ip', '')),
                str(a.get('dest_ip', '')),
                str(a.get('protocol', '')),
                str(a.get('attack_type', '')),
                str(a.get('risk_score', '')),
                str(a.get('severity', '')),
                str(a.get('status', '')),
            ])

        col_widths = [30, 100, 100, 60, 120, 40, 60, 70]
        alert_table = Table(table_data, colWidths=col_widths)

        # Style with severity-colored rows
        table_style_commands = [
            ('BACKGROUND', (0, 0), (-1, 0), CARD_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), RED_ACCENT),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (5, 0), (5, -1), 'CENTER'),
        ]

        for i, a in enumerate(display_alerts, 1):
            severity = a.get('severity', '')
            if severity == 'CRITICAL':
                table_style_commands.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor("#1a0808")))
                table_style_commands.append(('TEXTCOLOR', (0, i), (-1, i), RED_ACCENT))
            elif severity == 'HIGH':
                table_style_commands.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor("#1a1008")))
                table_style_commands.append(('TEXTCOLOR', (0, i), (-1, i), AMBER_ACCENT))
            else:
                table_style_commands.append(('BACKGROUND', (0, i), (-1, i), SURFACE_COLOR))
                table_style_commands.append(('TEXTCOLOR', (0, i), (-1, i), TEXT_PRIMARY))

        alert_table.setStyle(TableStyle(table_style_commands))
        elements.append(alert_table)

    # Footer
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR))
    elements.append(Paragraph(
        f"NetShield AI v1.0 — Confidential Security Report — {len(alerts)} events analyzed",
        ParagraphStyle('Footer', fontSize=8, textColor=TEXT_SECONDARY, alignment=TA_CENTER)
    ))

    doc.build(elements)
    return str(filepath)


def generate_csv_report(alerts: list, metrics: list = None) -> str:
    """Generate a CSV report and return the file path."""
    reports_dir = Path(settings.REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"netshield_report_{timestamp}.csv"
    filepath = reports_dir / filename

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        # Header
        writer.writerow(["NetShield AI Threat Report", f"Generated: {datetime.now().isoformat()}"])
        writer.writerow([])

        if metrics:
            writer.writerow(["=== MODEL METRICS ==="])
            writer.writerow(["Model", "Dataset", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"])
            for m in metrics:
                writer.writerow([
                    m.get('model_name', ''), m.get('dataset', ''),
                    m.get('accuracy', 0), m.get('precision_score', 0),
                    m.get('recall', 0), m.get('f1_score', 0), m.get('roc_auc', 0),
                ])
            writer.writerow([])

        writer.writerow(["=== ALERT DETAILS ==="])
        writer.writerow(["Source IP", "Dest IP", "Protocol", "Port", "Attack Type",
                         "Risk Score", "Severity", "Confidence", "Dataset", "Status"])
        for a in alerts:
            writer.writerow([
                a.get('source_ip', ''), a.get('dest_ip', ''), a.get('protocol', ''),
                a.get('port', ''), a.get('attack_type', ''), a.get('risk_score', ''),
                a.get('severity', ''), a.get('confidence', ''), a.get('dataset_source', ''),
                a.get('status', ''),
            ])

    return str(filepath)
