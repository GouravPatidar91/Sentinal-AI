import datetime
import json
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.app.models.models import Incident

def generate_incident_pdf(incident: Incident) -> bytes:
    """
    Generates a PDF report for the given incident and returns raw bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Styles for Dark-themed branding in PDF (deep blues and greys)
    title_style = ParagraphStyle(
        name="DocTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=24,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=15,
        alignment=0 # Left align
    )
    
    h1_style = ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        name="BodyTextCustom",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#334155"),
        spaceAfter=6,
        leading=14
    )
    
    code_style = ParagraphStyle(
        name="LogCodeText",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#475569"),
        spaceAfter=4,
        leading=10
    )
    
    bold_body_style = ParagraphStyle(
        name="BoldBodyText",
        parent=body_style,
        fontName="Helvetica-Bold"
    )

    story = []
    
    # ----------------------------------------------------
    # Header Branding Banner
    # ----------------------------------------------------
    story.append(Paragraph("SENTINELAI INCIDENT REPORT", title_style))
    story.append(Paragraph(f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
    story.append(Spacer(1, 10))
    
    # ----------------------------------------------------
    # Summary Table
    # ----------------------------------------------------
    severity_color = "#ef4444" if incident.severity.upper() == "CRITICAL" else "#f97316" if incident.severity.upper() == "HIGH" else "#eab308" if incident.severity.upper() == "WARNING" else "#3b82f6"
    
    summary_data = [
        [Paragraph("Incident ID", bold_body_style), Paragraph(f"INC-{incident.id}", body_style),
         Paragraph("Created At", bold_body_style), Paragraph(incident.created_at.strftime('%Y-%m-%d %H:%M:%S'), body_style)],
        [Paragraph("Risk Score", bold_body_style), Paragraph(f"{incident.risk_score}/100", body_style),
         Paragraph("Severity", bold_body_style), Paragraph(f"<font color='{severity_color}'><b>{incident.severity}</b></font>", body_style)],
        [Paragraph("Status", bold_body_style), Paragraph(incident.status, body_style),
         Paragraph("Anomaly Score", bold_body_style), Paragraph(f"{incident.anomaly_score:.2f}", body_style)]
    ]
    
    table = Table(summary_data, colWidths=[100, 150, 100, 150])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(table)
    story.append(Spacer(1, 15))
    
    # Title & Description
    story.append(Paragraph("Incident Title", h1_style))
    story.append(Paragraph(incident.title, body_style))
    story.append(Spacer(1, 5))
    
    story.append(Paragraph("Description", h1_style))
    story.append(Paragraph(incident.description, body_style))
    story.append(Spacer(1, 15))
    
    # ----------------------------------------------------
    # Correlated Attack Timeline
    # ----------------------------------------------------
    story.append(Paragraph("Correlated Event Timeline", h1_style))
    timeline_data = [
        [Paragraph("Timestamp", bold_body_style), Paragraph("Rule Name / Details", bold_body_style), Paragraph("Source Host / IP", bold_body_style)]
    ]
    
    for ev in incident.events:
        rule_name = ev.rule.name if ev.rule else "Anomaly Heuristics"
        host_ip = f"{ev.log_entry.host}"
        if ev.log_entry.src_ip:
            host_ip += f" ({ev.log_entry.src_ip})"
            
        timeline_data.append([
            Paragraph(ev.timestamp.strftime('%H:%M:%S'), body_style),
            Paragraph(f"<b>{rule_name}</b>: {ev.description}", body_style),
            Paragraph(host_ip, body_style)
        ])
        
    timeline_table = Table(timeline_data, colWidths=[70, 310, 120])
    timeline_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#cbd5e1")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 20))
    
    # ----------------------------------------------------
    # AI Threat Analysis & Remediation Report
    # ----------------------------------------------------
    if incident.ai_report:
        try:
            ai_data = json.loads(incident.ai_report)
            story.append(PageBreak()) # Push AI report to second page for clean separation
            
            story.append(Paragraph("SENTINELAI COGNITIVE SECURITY REPORT", title_style))
            story.append(Spacer(1, 10))
            
            story.append(Paragraph("Executive Summary", h1_style))
            story.append(Paragraph(ai_data.get("executive_summary", "N/A"), body_style))
            story.append(Spacer(1, 8))
            
            story.append(Paragraph("Technical Analysis", h1_style))
            story.append(Paragraph(ai_data.get("technical_analysis", "N/A"), body_style))
            story.append(Spacer(1, 8))
            
            story.append(Paragraph("Root Cause", h1_style))
            story.append(Paragraph(ai_data.get("root_cause", "N/A"), body_style))
            story.append(Spacer(1, 8))
            
            # Action Steps Table
            actions_data = [
                [Paragraph("Containment Steps", bold_body_style), Paragraph(ai_data.get("containment_steps", "N/A"), body_style)],
                [Paragraph("Recovery Steps", bold_body_style), Paragraph(ai_data.get("recovery_steps", "N/A"), body_style)],
                [Paragraph("SOC Recommendations", bold_body_style), Paragraph(ai_data.get("soc_recommendations", "N/A"), body_style)]
            ]
            actions_table = Table(actions_data, colWidths=[130, 370])
            actions_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f1f5f9")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 8),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            story.append(Paragraph("Remediation Action Plan", h1_style))
            story.append(actions_table)
            
        except Exception:
            # Fallback if AI report is plain text markdown
            story.append(Paragraph("AI Security Analysis", h1_style))
            story.append(Paragraph(incident.ai_report, body_style))
    else:
        story.append(Paragraph("AI Security Analysis", h1_style))
        story.append(Paragraph("No cognitive investigation has been generated for this incident yet.", body_style))

    # Build PDF
    doc.build(story)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
