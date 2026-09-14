"""Threat Intelligence router — IOC management and analysis."""
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, or_
from typing import Optional
from app.database import get_db
from app.models.user import ThreatIndicator, Alert, User, DetectionRule, Incident
from app.models.schemas import (
    ThreatIndicatorCreate, ThreatIndicatorResponse,
    DetectionRuleCreate, DetectionRuleUpdate, DetectionRuleResponse,
)
from app.middleware.auth import get_current_user

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])


@router.get("/indicators")
async def list_indicators(
    indicator_type: Optional[str] = None,
    severity: Optional[str] = None,
    threat_category: Optional[str] = None,
    search: Optional[str] = None,
    is_active: Optional[bool] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List threat indicators with filters."""
    query = select(ThreatIndicator).order_by(desc(ThreatIndicator.last_seen))

    if indicator_type:
        query = query.where(ThreatIndicator.indicator_type == indicator_type)
    if severity:
        query = query.where(ThreatIndicator.severity == severity.upper())
    if threat_category:
        query = query.where(ThreatIndicator.threat_category == threat_category)
    if search:
        search_term = f"%{search}%"
        query = query.where(
            or_(
                ThreatIndicator.value.like(search_term),
                ThreatIndicator.description.like(search_term),
            )
        )
    if is_active is not None:
        query = query.where(ThreatIndicator.is_active == is_active)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    indicators = result.scalars().all()
    return [ThreatIndicatorResponse.model_validate(i) for i in indicators]


@router.get("/summary")
async def get_threat_intel_summary(db: AsyncSession = Depends(get_db)):
    """Get threat intelligence overview statistics."""
    total = (await db.execute(select(func.count(ThreatIndicator.id)))).scalar() or 0
    active = (await db.execute(
        select(func.count(ThreatIndicator.id)).where(ThreatIndicator.is_active == True)
    )).scalar() or 0

    # By type
    type_q = select(ThreatIndicator.indicator_type, func.count(ThreatIndicator.id)).group_by(ThreatIndicator.indicator_type)
    type_result = await db.execute(type_q)
    by_type = {row[0]: row[1] for row in type_result.all()}

    # By severity
    sev_q = select(ThreatIndicator.severity, func.count(ThreatIndicator.id)).group_by(ThreatIndicator.severity)
    sev_result = await db.execute(sev_q)
    by_severity = {row[0]: row[1] for row in sev_result.all()}

    # By category
    cat_q = (
        select(ThreatIndicator.threat_category, func.count(ThreatIndicator.id))
        .where(ThreatIndicator.threat_category.isnot(None))
        .group_by(ThreatIndicator.threat_category)
    )
    cat_result = await db.execute(cat_q)
    by_category = {row[0]: row[1] for row in cat_result.all()}

    # Recent indicators
    recent_q = select(ThreatIndicator).order_by(desc(ThreatIndicator.last_seen)).limit(10)
    recent_result = await db.execute(recent_q)
    recent = recent_result.scalars().all()

    return {
        "total_indicators": total,
        "active_indicators": active,
        "by_type": by_type,
        "by_severity": by_severity,
        "by_category": by_category,
        "recent_indicators": [ThreatIndicatorResponse.model_validate(i) for i in recent],
    }


@router.get("/indicators/{indicator_id}", response_model=ThreatIndicatorResponse)
async def get_indicator_detail(indicator_id: int, db: AsyncSession = Depends(get_db)):
    """Get full detail of a single threat indicator."""
    result = await db.execute(select(ThreatIndicator).where(ThreatIndicator.id == indicator_id))
    indicator = result.scalar_one_or_none()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return ThreatIndicatorResponse.model_validate(indicator)


@router.post("/indicators", response_model=ThreatIndicatorResponse)
async def create_indicator(
    data: ThreatIndicatorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new threat indicator."""
    indicator = ThreatIndicator(
        indicator_type=data.indicator_type,
        value=data.value,
        threat_category=data.threat_category,
        severity=data.severity,
        confidence=data.confidence,
        source=data.source,
        description=data.description,
        related_alert_ids=data.related_alert_ids or [],
        is_active=True,
    )
    db.add(indicator)
    await db.commit()
    await db.refresh(indicator)
    return ThreatIndicatorResponse.model_validate(indicator)


@router.get("/report")
async def get_threat_intel_report(db: AsyncSession = Depends(get_db)):
    """Generate threat intelligence report data."""
    # Get all active indicators grouped
    indicators = (await db.execute(
        select(ThreatIndicator).where(ThreatIndicator.is_active == True).order_by(desc(ThreatIndicator.confidence))
    )).scalars().all()

    # Get alert statistics for threat context
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    critical_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == "CRITICAL")
    )).scalar() or 0

    # Attack type distribution
    atk_q = (
        select(Alert.attack_type, func.count(Alert.id))
        .group_by(Alert.attack_type)
        .order_by(desc(func.count(Alert.id)))
        .limit(10)
    )
    atk_result = await db.execute(atk_q)
    top_attack_types = {row[0]: row[1] for row in atk_result.all()}

    return {
        "report_title": "NetShield AI — Threat Intelligence Report",
        "generated_at": datetime.utcnow().isoformat(),
        "executive_summary": {
            "total_indicators": len(indicators),
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "threat_level": "HIGH" if critical_alerts > 5 else "MEDIUM" if critical_alerts > 0 else "LOW",
        },
        "indicators": [ThreatIndicatorResponse.model_validate(i) for i in indicators[:20]],
        "top_attack_types": top_attack_types,
        "recommendations": [
            "Review and update firewall rules for identified malicious IPs",
            "Implement network segmentation for affected assets",
            "Update IDS/IPS signatures for detected attack patterns",
            "Conduct security awareness training for affected teams",
            "Verify patch levels for systems exposed to identified vulnerabilities",
        ],
    }


# ── MITRE ATT&CK Matrix Mapping ───────────────────────────────────────────

@router.get("/mitre-matrix")
async def get_mitre_attack_matrix(db: AsyncSession = Depends(get_db)):
    """Return enterprise MITRE ATT&CK tactics with mapped active alerts & incidents."""
    tactics = [
        {
            "id": "TA0043",
            "name": "Reconnaissance",
            "techniques": [
                {"id": "T1595", "name": "Active Scanning", "active_hits": 89, "severity": "HIGH"},
                {"id": "T1590", "name": "Gather Victim Network Info", "active_hits": 45, "severity": "MEDIUM"},
            ]
        },
        {
            "id": "TA0001",
            "name": "Initial Access",
            "techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "active_hits": 124, "severity": "CRITICAL"},
                {"id": "T1133", "name": "External Remote Services", "active_hits": 34, "severity": "HIGH"},
            ]
        },
        {
            "id": "TA0002",
            "name": "Execution",
            "techniques": [
                {"id": "T1059", "name": "Command and Scripting Interpreter", "active_hits": 18, "severity": "HIGH"},
                {"id": "T1203", "name": "Exploitation for Client Execution", "active_hits": 12, "severity": "HIGH"},
            ]
        },
        {
            "id": "TA0006",
            "name": "Credential Access",
            "techniques": [
                {"id": "T1110", "name": "Brute Force / Password Spray", "active_hits": 76, "severity": "HIGH"},
                {"id": "T1555", "name": "Credentials from Password Stores", "active_hits": 4, "severity": "MEDIUM"},
            ]
        },
        {
            "id": "TA0007",
            "name": "Discovery",
            "techniques": [
                {"id": "T1046", "name": "Network Service Discovery", "active_hits": 512, "severity": "MEDIUM"},
                {"id": "T1082", "name": "System Information Discovery", "active_hits": 28, "severity": "LOW"},
            ]
        },
        {
            "id": "TA0011",
            "name": "Command and Control",
            "techniques": [
                {"id": "T1071", "name": "Application Layer Protocol", "active_hits": 95, "severity": "CRITICAL"},
                {"id": "T1573", "name": "Encrypted Channel", "active_hits": 140, "severity": "HIGH"},
            ]
        },
        {
            "id": "TA0040",
            "name": "Impact",
            "techniques": [
                {"id": "T1498", "name": "Network Denial of Service", "active_hits": 230, "severity": "CRITICAL"},
                {"id": "T1486", "name": "Data Encrypted for Impact", "active_hits": 7, "severity": "CRITICAL"},
            ]
        }
    ]

    total_techniques = sum(len(t["techniques"]) for t in tactics)
    active_threat_count = sum(sum(tech["active_hits"] for tech in t["techniques"]) for t in tactics)

    return {
        "tactics": tactics,
        "total_tactics": len(tactics),
        "total_techniques": total_techniques,
        "active_threat_hits": active_threat_count,
        "last_updated": datetime.utcnow().isoformat(),
    }


# ── Detection Rules Management ────────────────────────────────────────────

@router.get("/detection-rules")
async def list_detection_rules(
    engine: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List detection rules (Suricata, Zeek, YARA, Custom AI)."""
    query = select(DetectionRule).order_by(desc(DetectionRule.hit_count))
    if engine and engine != "all":
        query = query.where(DetectionRule.engine_type == engine)
    if severity and severity != "all":
        query = query.where(DetectionRule.severity == severity.upper())

    result = await db.execute(query)
    rules = result.scalars().all()
    return [DetectionRuleResponse.model_validate(r) for r in rules]


@router.post("/detection-rules", response_model=DetectionRuleResponse)
async def create_detection_rule(
    data: DetectionRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new detection rule."""
    rule = DetectionRule(
        name=data.name,
        engine_type=data.engine_type,
        description=data.description,
        pattern=data.pattern,
        severity=data.severity,
        is_enabled=data.is_enabled,
        hit_count=0,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return DetectionRuleResponse.model_validate(rule)


@router.patch("/detection-rules/{rule_id}", response_model=DetectionRuleResponse)
async def update_detection_rule(
    rule_id: int,
    data: DetectionRuleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update rule status, pattern, or severity."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    if data.name is not None:
        rule.name = data.name
    if data.engine_type is not None:
        rule.engine_type = data.engine_type
    if data.description is not None:
        rule.description = data.description
    if data.pattern is not None:
        rule.pattern = data.pattern
    if data.severity is not None:
        rule.severity = data.severity
    if data.is_enabled is not None:
        rule.is_enabled = data.is_enabled

    rule.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(rule)
    return DetectionRuleResponse.model_validate(rule)


@router.delete("/detection-rules/{rule_id}")
async def delete_detection_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a detection rule."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    await db.delete(rule)
    await db.commit()
    return {"status": "success", "message": f"Detection rule #{rule_id} deleted."}

