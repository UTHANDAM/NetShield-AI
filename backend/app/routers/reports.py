"""Reports router — Generate and download CSV/PDF threat reports."""
import os
import csv
from datetime import datetime
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.user import Alert, ModelMetric, Report
from app.models.schemas import ReportRequest, ReportResponse
from app.config import settings

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate")
async def generate_report(
    req: ReportRequest,
    db: AsyncSession = Depends(get_db),
):
    """Generate a threat report (CSV or PDF)."""
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    # Fetch alerts for the report
    result = await db.execute(select(Alert).order_by(Alert.detected_at.desc()).limit(500))
    alerts = result.scalars().all()

    # Convert alerts and metrics to dicts for report generator
    alert_dicts = []
    for a in alerts:
        alert_dicts.append({
            "id": a.id,
            "source_ip": a.source_ip,
            "dest_ip": a.dest_ip,
            "protocol": a.protocol,
            "port": a.port,
            "attack_type": a.attack_type,
            "risk_score": a.risk_score,
            "severity": a.severity,
            "confidence": a.confidence,
            "dataset_source": a.dataset_source,
            "detected_at": a.detected_at,
            "status": a.status,
        })

    metric_dicts = []
    if req.include_metrics:
        metrics_result = await db.execute(select(ModelMetric))
        metrics = metrics_result.scalars().all()
        for m in metrics:
            metric_dicts.append({
                "model_name": m.model_name,
                "dataset": m.dataset,
                "model_type": m.model_type,
                "accuracy": m.accuracy,
                "precision_score": m.precision_score,
                "recall": m.recall,
                "f1_score": m.f1_score,
                "roc_auc": m.roc_auc,
            })

    from app.services.report_generator import generate_pdf_report, generate_csv_report

    if req.report_type.lower() == "pdf":
        try:
            filepath = generate_pdf_report(alert_dicts, metric_dicts, title=req.title or "NetShield AI — Threat Intelligence Report")
        except Exception as e:
            print(f"[Reports] PDF generation failed, falling back to CSV: {e}")
            filepath = generate_csv_report(alert_dicts, metric_dicts)
    else:
        filepath = generate_csv_report(alert_dicts, metric_dicts)

    record_count = len(alert_dicts)

    # Save report metadata
    report = Report(
        title=req.title or "NetShield AI Threat Report",
        report_type=req.report_type,
        file_path=filepath,
        record_count=record_count,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return ReportResponse.model_validate(report)


@router.get("/")
async def list_reports(db: AsyncSession = Depends(get_db)):
    """List all generated reports."""
    result = await db.execute(select(Report).order_by(Report.created_at.desc()))
    reports = result.scalars().all()
    return [ReportResponse.model_validate(r) for r in reports]


@router.get("/download/{report_id}")
async def download_report(report_id: int, db: AsyncSession = Depends(get_db)):
    """Download a specific report file."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report or not os.path.exists(report.file_path):
        return {"error": "Report not found"}

    return FileResponse(
        report.file_path,
        filename=os.path.basename(report.file_path),
        media_type="application/octet-stream",
    )


@router.get("/risk-summary")
async def get_risk_summary(db: AsyncSession = Depends(get_db)):
    """Get overall risk summary for the reports dashboard."""
    # Severity distribution from all alerts
    sev_q = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    sev_result = await db.execute(sev_q)
    severity_counts = {row[0]: row[1] for row in sev_result.all()}

    total = sum(severity_counts.values()) or 1

    # Calculate weighted overall risk score
    weights = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 20}
    weighted_sum = sum(weights.get(sev, 0) * count for sev, count in severity_counts.items())
    overall_risk = int(weighted_sum / total)

    # Determine risk level
    if overall_risk >= 80:
        risk_level = "CRITICAL"
    elif overall_risk >= 60:
        risk_level = "HIGH"
    elif overall_risk >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "overall_risk_score": overall_risk,
        "risk_level": risk_level,
        "severity_distribution": severity_counts,
        "total_alerts": total,
        "risk_breakdown": {
            sev: round(count / total * 100, 1)
            for sev, count in severity_counts.items()
        },
    }
