"""Anomaly Detection router — Run ML models on traffic data."""
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.user import TrafficRecord, Alert
from app.models.schemas import (
    DetectionRequest, AnomalyResult, PredictionRequest, PredictionResponse
)
from app.services.ml_engine import ml_engine

router = APIRouter(prefix="/api/anomaly", tags=["Anomaly Detection"])


@router.post("/detect")
async def run_anomaly_detection(
    req: DetectionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Run anomaly detection on a sample of traffic records from the database.
    Uses the binary model to flag Normal vs Attack, then the multiclass model
    to classify the specific attack type.
    """
    # Fetch sample traffic records
    query = (
        select(TrafficRecord)
        .where(TrafficRecord.dataset_source == req.dataset)
        .order_by(func.random())
        .limit(req.sample_size)
    )
    result = await db.execute(query)
    records = result.scalars().all()

    if not records:
        return {"message": "No traffic records found for this dataset", "results": []}

    # Get feature columns from preprocessor
    feature_cols = ml_engine.get_feature_columns(req.dataset)

    results = []
    new_alerts = 0

    for record in records:
        # Build feature dict (use what we have, default 0 for missing)
        features = {}
        for col in feature_cols:
            features[col] = getattr(record, col, 0) if hasattr(record, col) else 0

        # Use port and duration if available
        if record.port:
            # Map to common feature names
            if "Destination Port" in feature_cols or "Destination_Port" in feature_cols:
                features["Destination Port"] = record.port
                features["Destination_Port"] = record.port
            if "dsport" in feature_cols:
                features["dsport"] = record.port
        if record.duration:
            if "Flow Duration" in feature_cols or "Flow_Duration" in feature_cols:
                features["Flow Duration"] = record.duration
                features["Flow_Duration"] = record.duration
            if "dur" in feature_cols:
                features["dur"] = record.duration
        if record.packet_size:
            if "sbytes" in feature_cols:
                features["sbytes"] = record.packet_size

        # Run binary prediction
        binary_result = ml_engine.predict(features, req.dataset, "binary")

        # If anomaly detected, also run multiclass for specific type
        attack_type = binary_result["attack_type"]
        if binary_result["is_anomaly"]:
            multi_result = ml_engine.predict(features, req.dataset, "multiclass")
            if multi_result.get("attack_type") and multi_result["attack_type"] != "Unknown":
                attack_type = multi_result["attack_type"]

        anomaly_result = AnomalyResult(
            source_ip=record.source_ip,
            dest_ip=record.dest_ip,
            protocol=record.protocol,
            is_anomaly=binary_result["is_anomaly"],
            attack_type=attack_type,
            confidence=binary_result["confidence"],
            risk_score=binary_result["risk_score"],
            severity=binary_result["severity"],
            model_used=f"XGBoost ({req.dataset})",
            detected_at=datetime.utcnow(),
        )
        results.append(anomaly_result)

        # Create alert for detected anomalies
        if binary_result["is_anomaly"]:
            alert = Alert(
                source_ip=record.source_ip,
                dest_ip=record.dest_ip,
                protocol=record.protocol,
                port=record.port,
                attack_type=attack_type,
                risk_score=binary_result["risk_score"],
                severity=binary_result["severity"],
                confidence=binary_result["confidence"],
                dataset_source=req.dataset,
                status="new",
            )
            db.add(alert)
            await db.flush()
            new_alerts += 1
            
            # Milestone 3 Automation: Auto-escalate CRITICAL alerts to Incidents
            if alert.severity == "CRITICAL":
                from app.models.user import Incident, IncidentNote, ThreatIndicator, Notification
                
                # 1. Create Incident
                incident = Incident(
                    title=f"Auto-Escalated: {alert.attack_type} Attack",
                    description=f"CRITICAL severity anomaly detected. Source: {alert.source_ip}, Target: {alert.dest_ip}:{alert.port}.",
                    severity="CRITICAL",
                    status="detection",
                    assigned_analyst=None,
                    related_alert_ids=[alert.id],
                    attack_category=alert.attack_type,
                    response_actions=[],
                )
                db.add(incident)
                await db.flush()
                
                alert.incident_id = incident.id
                
                # 2. Add Timeline Note
                note = IncidentNote(
                    incident_id=incident.id,
                    author="System AI",
                    content="Incident auto-created from critical severity alert.",
                    note_type="timeline",
                )
                db.add(note)
                
                # 3. Create Threat Indicator
                indicator = ThreatIndicator(
                    indicator_type="ip",
                    value=alert.source_ip,
                    threat_category=alert.attack_type,
                    severity="CRITICAL",
                    confidence=alert.confidence,
                    source="internal_detection",
                    description=f"Auto-generated IP indicator from {alert.attack_type} attack.",
                    related_alert_ids=[alert.id],
                    is_active=True,
                )
                db.add(indicator)
                await db.flush()
                
                # 4. Push Notification
                notif = Notification(
                    title=f"CRITICAL: {alert.attack_type} Detected",
                    message=f"High-risk anomaly detected from {alert.source_ip}. Incident #{incident.id} auto-created.",
                    severity="CRITICAL",
                    notif_type="incident",
                    related_id=incident.id,
                    related_type="incident",
                    is_read=False,
                )
                db.add(notif)

    await db.commit()

    return {
        "total_analyzed": len(records),
        "anomalies_detected": sum(1 for r in results if r.is_anomaly),
        "new_alerts_created": new_alerts,
        "results": results,
    }


@router.post("/predict", response_model=PredictionResponse)
async def predict_single(req: PredictionRequest):
    """Run a single prediction with custom features (manual testing interface)."""
    result = ml_engine.predict(
        features=req.features,
        dataset=req.dataset,
        model_type=req.model_type,
    )
    return PredictionResponse(**result)


@router.get("/summary")
async def get_anomaly_summary(db: AsyncSession = Depends(get_db)):
    """Get anomaly detection summary stats for the dashboard."""
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    open_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "open")
    )).scalar() or 0

    # Attack type distribution from alerts
    atk_q = (
        select(Alert.attack_type, func.count(Alert.id))
        .group_by(Alert.attack_type)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )
    atk_result = await db.execute(atk_q)
    attack_distribution = {row[0]: row[1] for row in atk_result.all()}

    # Severity distribution
    sev_q = (
        select(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
    )
    sev_result = await db.execute(sev_q)
    severity_distribution = {row[0]: row[1] for row in sev_result.all()}

    # Average risk score
    avg_risk = (await db.execute(select(func.avg(Alert.risk_score)))).scalar() or 0

    # Recent detections
    recent_q = select(Alert).order_by(Alert.detected_at.desc()).limit(10)
    recent_result = await db.execute(recent_q)
    recent = recent_result.scalars().all()

    return {
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "avg_risk_score": round(avg_risk, 1),
        "attack_distribution": attack_distribution,
        "severity_distribution": severity_distribution,
        "recent_detections": [
            {
                "id": a.id,
                "source_ip": a.source_ip,
                "dest_ip": a.dest_ip,
                "attack_type": a.attack_type,
                "confidence": a.confidence,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "detected_at": a.detected_at.isoformat() if a.detected_at else None,
                "status": a.status,
            }
            for a in recent
        ],
    }
