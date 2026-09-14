"""Alerts router — Full alert lifecycle, search, detail, notes, metrics."""
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, update, or_, and_, cast, String
from typing import Optional
from app.database import get_db
from app.models.user import Alert, Notification, Incident
from app.models.schemas import AlertResponse, AlertStats, AlertUpdateRequest
from app.middleware.auth import get_current_user
from app.services.notification_service import create_notification

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/")
async def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    dataset: Optional[str] = None,
    attack_type: Optional[str] = None,
    assigned_to: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Get paginated alert list with full filtering and search."""
    query = select(Alert).order_by(desc(Alert.detected_at))

    if severity:
        query = query.where(Alert.severity == severity.upper())
    if status:
        query = query.where(Alert.status == status)
    if dataset:
        query = query.where(Alert.dataset_source == dataset)
    if attack_type:
        query = query.where(Alert.attack_type == attack_type)
    if assigned_to:
        query = query.where(Alert.assigned_to == assigned_to)
    if search:
        search_term = f"%{search}%"
        query = query.where(
            or_(
                Alert.source_ip.like(search_term),
                Alert.dest_ip.like(search_term),
                Alert.attack_type.like(search_term),
                Alert.asset.like(search_term),
            )
        )
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            query = query.where(Alert.detected_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            query = query.where(Alert.detected_at <= dt_to)
        except ValueError:
            pass

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    alerts = result.scalars().all()
    return [AlertResponse.model_validate(a) for a in alerts]


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(db: AsyncSession = Depends(get_db)):
    """Get alert count by severity and status, plus MTTA/MTTR."""
    total = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    critical = (await db.execute(select(func.count(Alert.id)).where(Alert.severity == "CRITICAL"))).scalar() or 0
    high = (await db.execute(select(func.count(Alert.id)).where(Alert.severity == "HIGH"))).scalar() or 0
    medium = (await db.execute(select(func.count(Alert.id)).where(Alert.severity == "MEDIUM"))).scalar() or 0
    low = (await db.execute(select(func.count(Alert.id)).where(Alert.severity == "LOW"))).scalar() or 0
    open_count = (await db.execute(select(func.count(Alert.id)).where(Alert.status.in_(["new", "open"])))).scalar() or 0
    new_count = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "new"))).scalar() or 0
    ack_count = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "acknowledged"))).scalar() or 0
    inv_count = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "investigating"))).scalar() or 0
    esc_count = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "escalated"))).scalar() or 0
    res_count = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "resolved"))).scalar() or 0

    # MTTA: average time from detected_at to acknowledged_at (for alerts that have been acknowledged)
    mtta_result = await db.execute(
        select(
            func.avg(
                func.julianday(Alert.acknowledged_at) - func.julianday(Alert.detected_at)
            )
        ).where(Alert.acknowledged_at.isnot(None))
    )
    mtta_days = mtta_result.scalar()
    mtta_minutes = round(mtta_days * 24 * 60, 1) if mtta_days else None

    # MTTR: average time from detected_at to resolved_at
    mttr_result = await db.execute(
        select(
            func.avg(
                func.julianday(Alert.resolved_at) - func.julianday(Alert.detected_at)
            )
        ).where(Alert.resolved_at.isnot(None))
    )
    mttr_days = mttr_result.scalar()
    mttr_minutes = round(mttr_days * 24 * 60, 1) if mttr_days else None

    return AlertStats(
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        open_count=open_count,
        new_count=new_count,
        acknowledged_count=ack_count,
        investigating_count=inv_count,
        escalated_count=esc_count,
        resolved_count=res_count,
        mtta_minutes=mtta_minutes,
        mttr_minutes=mttr_minutes,
    )


@router.get("/attack-types")
async def get_attack_types(db: AsyncSession = Depends(get_db)):
    """Get all distinct attack types for filter dropdowns."""
    result = await db.execute(
        select(Alert.attack_type).distinct().where(Alert.attack_type.isnot(None))
    )
    return [row[0] for row in result.all()]


@router.get("/timeline")
async def get_alerts_timeline(
    days: int = Query(default=7, le=90),
    db: AsyncSession = Depends(get_db),
):
    """Get alert counts grouped by date for timeline charts."""
    result = await db.execute(
        select(
            func.date(Alert.detected_at).label("date"),
            Alert.severity,
            func.count(Alert.id).label("count")
        )
        .group_by(func.date(Alert.detected_at), Alert.severity)
        .order_by(func.date(Alert.detected_at))
    )
    rows = result.all()
    timeline = {}
    for row in rows:
        date_str = str(row[0]) if row[0] else "Unknown"
        if date_str not in timeline:
            timeline[date_str] = {"date": date_str, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
        if row[1] in timeline[date_str]:
            timeline[date_str][row[1]] = row[2]
        timeline[date_str]["total"] += row[2]

    return list(timeline.values())


@router.get("/{alert_id}")
async def get_alert_detail(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Get full detail of a single alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: int,
    new_status: str = Query(..., description="new, acknowledged, investigating, escalated, resolved, closed"),
    db: AsyncSession = Depends(get_db),
):
    """Update alert status with lifecycle timestamps."""
    valid = ["new", "open", "acknowledged", "investigating", "escalated", "resolved", "closed"]
    if new_status not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(valid)}")

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = datetime.utcnow()
    alert.status = new_status

    if new_status == "acknowledged" and not alert.acknowledged_at:
        alert.acknowledged_at = now
    elif new_status == "resolved" and not alert.resolved_at:
        alert.resolved_at = now
    elif new_status == "closed" and not alert.closed_at:
        alert.closed_at = now
    if new_status == "escalated" and not alert.incident_id:
        incident = Incident(
            title=f"Escalated Alert: {alert.attack_type}",
            description=f"Auto-escalated from alert {alert.id}. Source: {alert.source_ip}",
            severity=alert.severity,
            status="detection",
            assigned_analyst=alert.assigned_to,
            affected_assets=[alert.dest_ip] if alert.dest_ip else [],
            related_alert_ids=[alert.id],
            attack_category=alert.attack_type,
        )
        db.add(incident)
        await db.flush()
        alert.incident_id = incident.id

    await db.commit()
    return {"message": f"Alert {alert_id} status updated to {new_status}"}


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: int,
    data: AlertUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update alert fields (status, assignment, notes, severity)."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = datetime.utcnow()

    if data.status:
        alert.status = data.status
        if data.status == "acknowledged" and not alert.acknowledged_at:
            alert.acknowledged_at = now
        elif data.status == "resolved" and not alert.resolved_at:
            alert.resolved_at = now
        elif data.status == "closed" and not alert.closed_at:
            alert.closed_at = now
    if data.assigned_to is not None:
        alert.assigned_to = data.assigned_to
    if data.notes is not None:
        alert.notes = data.notes
    if data.severity is not None:
        alert.severity = data.severity
    if data.status == "escalated" and not alert.incident_id:
        incident = Incident(
            title=f"Escalated Alert: {alert.attack_type}",
            description=f"Auto-escalated from alert {alert.id}. Source: {alert.source_ip}",
            severity=alert.severity,
            status="detection",
            assigned_analyst=alert.assigned_to,
            affected_assets=[alert.dest_ip] if alert.dest_ip else [],
            related_alert_ids=[alert.id],
            attack_category=alert.attack_type,
        )
        db.add(incident)
        await db.flush()
        alert.incident_id = incident.id

    await db.commit()

    # Auto-notify on escalation
    if data.status == "escalated":
        await create_notification(
            db,
            title=f"Alert #{alert_id} Escalated",
            message=f"{alert.attack_type} alert escalated. Source: {alert.source_ip}",
            severity=alert.severity,
            notif_type="alert",
            related_id=alert_id,
            related_type="alert",
        )
        await db.commit()

    return AlertResponse.model_validate(alert)
