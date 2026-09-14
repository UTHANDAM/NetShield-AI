"""Analytics router — Security analytics dashboard data."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.database import get_db
from app.models.user import Alert, Incident, TrafficRecord, ThreatIndicator

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


@router.get("/security-overview")
async def security_overview(db: AsyncSession = Depends(get_db)):
    """Aggregated security metrics for the analytics dashboard."""
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    open_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status.in_(["new", "open", "acknowledged", "investigating"]))
    )).scalar() or 0
    critical_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == "CRITICAL")
    )).scalar() or 0

    total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    active_incidents = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status.notin_(["resolution", "closed"]))
    )).scalar() or 0
    resolved_incidents = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status.in_(["resolution", "closed"]))
    )).scalar() or 0

    total_indicators = (await db.execute(select(func.count(ThreatIndicator.id)))).scalar() or 0

    avg_risk = (await db.execute(select(func.avg(Alert.risk_score)))).scalar() or 0

    # MTTA
    mtta_result = await db.execute(
        select(
            func.avg(func.julianday(Alert.acknowledged_at) - func.julianday(Alert.detected_at))
        ).where(Alert.acknowledged_at.isnot(None))
    )
    mtta_days = mtta_result.scalar()
    mtta_minutes = round(mtta_days * 24 * 60, 1) if mtta_days else None

    # MTTR
    mttr_result = await db.execute(
        select(
            func.avg(func.julianday(Alert.resolved_at) - func.julianday(Alert.detected_at))
        ).where(Alert.resolved_at.isnot(None))
    )
    mttr_days = mttr_result.scalar()
    mttr_minutes = round(mttr_days * 24 * 60, 1) if mttr_days else None

    return {
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "resolved_incidents": resolved_incidents,
        "total_indicators": total_indicators,
        "avg_risk_score": round(avg_risk, 1),
        "mtta_minutes": mtta_minutes,
        "mttr_minutes": mttr_minutes,
    }


@router.get("/alerts-timeline")
async def alerts_timeline(db: AsyncSession = Depends(get_db)):
    """Alerts grouped by date for timeline/trend charts."""
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


@router.get("/attack-distribution")
async def attack_distribution(db: AsyncSession = Depends(get_db)):
    """Attack types, severity, and protocol distribution."""
    # By attack type
    atk_q = (
        select(Alert.attack_type, func.count(Alert.id))
        .where(Alert.attack_type.isnot(None))
        .group_by(Alert.attack_type)
        .order_by(desc(func.count(Alert.id)))
    )
    atk_result = await db.execute(atk_q)
    by_attack_type = [{"name": row[0], "value": row[1]} for row in atk_result.all()]

    # By severity
    sev_q = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    sev_result = await db.execute(sev_q)
    by_severity = [{"name": row[0], "value": row[1]} for row in sev_result.all()]

    # By status
    st_q = select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    st_result = await db.execute(st_q)
    by_status = [{"name": row[0], "value": row[1]} for row in st_result.all()]

    return {
        "by_attack_type": by_attack_type,
        "by_severity": by_severity,
        "by_status": by_status,
    }


@router.get("/top-attackers")
async def top_attackers(
    limit: int = Query(default=10, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Top source IPs by alert count."""
    result = await db.execute(
        select(Alert.source_ip, func.count(Alert.id).label("count"), func.max(Alert.severity).label("max_severity"))
        .where(Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(desc("count"))
        .limit(limit)
    )
    return [{"ip": row[0], "count": row[1], "max_severity": row[2]} for row in result.all()]


@router.get("/top-targets")
async def top_targets(
    limit: int = Query(default=10, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Top destination IPs by alert count."""
    result = await db.execute(
        select(Alert.dest_ip, func.count(Alert.id).label("count"), func.max(Alert.severity).label("max_severity"))
        .where(Alert.dest_ip.isnot(None))
        .group_by(Alert.dest_ip)
        .order_by(desc("count"))
        .limit(limit)
    )
    return [{"ip": row[0], "count": row[1], "max_severity": row[2]} for row in result.all()]


@router.get("/network-analytics")
async def network_analytics(db: AsyncSession = Depends(get_db)):
    """Top ports, protocols, and suspicious connection analytics."""
    # Top ports (from alerts)
    port_q = (
        select(Alert.port, func.count(Alert.id).label("count"))
        .where(Alert.port.isnot(None))
        .group_by(Alert.port)
        .order_by(desc("count"))
        .limit(10)
    )
    port_result = await db.execute(port_q)
    top_ports = [{"port": row[0], "count": row[1]} for row in port_result.all()]

    # Top protocols
    proto_q = (
        select(Alert.protocol, func.count(Alert.id).label("count"))
        .where(Alert.protocol.isnot(None))
        .group_by(Alert.protocol)
        .order_by(desc("count"))
    )
    proto_result = await db.execute(proto_q)
    top_protocols = [{"protocol": row[0], "count": row[1]} for row in proto_result.all()]

    # Suspicious connections (high risk score alerts)
    susp_q = (
        select(Alert)
        .where(Alert.risk_score >= 80)
        .order_by(desc(Alert.detected_at))
        .limit(10)
    )
    susp_result = await db.execute(susp_q)
    suspicious = susp_result.scalars().all()

    return {
        "top_ports": top_ports,
        "top_protocols": top_protocols,
        "suspicious_connections": [
            {
                "id": a.id,
                "source_ip": a.source_ip,
                "dest_ip": a.dest_ip,
                "port": a.port,
                "protocol": a.protocol,
                "attack_type": a.attack_type,
                "risk_score": a.risk_score,
                "severity": a.severity,
            }
            for a in suspicious
        ],
    }


@router.get("/incident-metrics")
async def incident_metrics(db: AsyncSession = Depends(get_db)):
    """Incident-specific analytics for the dashboard."""
    # Incidents over time
    timeline_q = (
        select(
            func.date(Incident.created_at).label("date"),
            func.count(Incident.id).label("count")
        )
        .group_by(func.date(Incident.created_at))
        .order_by(func.date(Incident.created_at))
    )
    timeline_result = await db.execute(timeline_q)
    timeline = [{"date": str(row[0]), "count": row[1]} for row in timeline_result.all()]

    # By severity
    sev_q = select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    sev_result = await db.execute(sev_q)
    by_severity = [{"name": row[0], "value": row[1]} for row in sev_result.all()]

    # By status
    st_q = select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    st_result = await db.execute(st_q)
    by_status = [{"name": row[0], "value": row[1]} for row in st_result.all()]

    return {
        "timeline": timeline,
        "by_severity": by_severity,
        "by_status": by_status,
    }
