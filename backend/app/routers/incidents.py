"""Incidents router — Full incident management lifecycle."""
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, update
from typing import Optional
from app.database import get_db
from app.models.user import Incident, IncidentNote, Alert, User, SoarAction
from app.models.schemas import (
    IncidentCreate, IncidentUpdate, IncidentResponse,
    IncidentNoteCreate, IncidentNoteResponse, AlertResponse,
    SoarActionCreate, SoarActionResponse,
)
from app.middleware.auth import get_current_user
from app.services.notification_service import auto_notify_on_incident

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.post("/", response_model=IncidentResponse)
async def create_incident(
    data: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new incident, optionally linking alerts."""
    incident = Incident(
        title=data.title,
        description=data.description,
        severity=data.severity,
        status="detection",
        assigned_analyst=data.assigned_analyst or current_user.name,
        affected_assets=data.affected_assets or [],
        related_alert_ids=data.related_alert_ids or [],
        attack_category=data.attack_category,
        indicators=data.indicators or [],
        response_actions=[],
    )
    db.add(incident)
    await db.flush()

    # Link alerts to this incident
    if data.related_alert_ids:
        for alert_id in data.related_alert_ids:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if alert:
                alert.incident_id = incident.id

    # Auto-create timeline note
    note = IncidentNote(
        incident_id=incident.id,
        author=current_user.name,
        content=f"Incident created by {current_user.name}. Severity: {data.severity}.",
        note_type="timeline",
    )
    db.add(note)

    # Auto-notify
    await auto_notify_on_incident(db, incident, "created")

    await db.commit()
    await db.refresh(incident)
    return IncidentResponse.model_validate(incident)


@router.get("/")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List incidents with filters."""
    query = select(Incident).order_by(desc(Incident.created_at))

    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity.upper())
    if assigned:
        query = query.where(Incident.assigned_analyst.like(f"%{assigned}%"))
    if search:
        search_term = f"%{search}%"
        query = query.where(
            Incident.title.like(search_term) | Incident.description.like(search_term)
        )

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    incidents = result.scalars().all()
    return [IncidentResponse.model_validate(i) for i in incidents]


@router.get("/metrics")
async def get_incident_metrics(db: AsyncSession = Depends(get_db)):
    """Get incident analytics: counts, MTTA, MTTR, by severity/status."""
    total = (await db.execute(select(func.count(Incident.id)))).scalar() or 0

    # By status
    status_q = select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    status_result = await db.execute(status_q)
    by_status = {row[0]: row[1] for row in status_result.all()}

    # By severity
    sev_q = select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    sev_result = await db.execute(sev_q)
    by_severity = {row[0]: row[1] for row in sev_result.all()}

    # By category
    cat_q = (
        select(Incident.attack_category, func.count(Incident.id))
        .where(Incident.attack_category.isnot(None))
        .group_by(Incident.attack_category)
    )
    cat_result = await db.execute(cat_q)
    by_category = {row[0]: row[1] for row in cat_result.all()}

    # Active (not closed/resolved)
    active = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.notin_(["resolution", "closed"])
        )
    )).scalar() or 0

    # MTTR for resolved/closed incidents
    mttr_result = await db.execute(
        select(
            func.avg(
                func.julianday(Incident.closed_at) - func.julianday(Incident.created_at)
            )
        ).where(Incident.closed_at.isnot(None))
    )
    mttr_days = mttr_result.scalar()
    mttr_hours = round(mttr_days * 24, 1) if mttr_days else None

    return {
        "total": total,
        "active": active,
        "by_status": by_status,
        "by_severity": by_severity,
        "by_category": by_category,
        "mttr_hours": mttr_hours,
    }


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident_detail(incident_id: int, db: AsyncSession = Depends(get_db)):
    """Get full incident detail."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentResponse.model_validate(incident)


@router.get("/{incident_id}/notes")
async def get_incident_notes(incident_id: int, db: AsyncSession = Depends(get_db)):
    """Get all notes/timeline for an incident."""
    result = await db.execute(
        select(IncidentNote)
        .where(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at)
    )
    notes = result.scalars().all()
    return [IncidentNoteResponse.model_validate(n) for n in notes]


@router.get("/{incident_id}/alerts")
async def get_incident_alerts(incident_id: int, db: AsyncSession = Depends(get_db)):
    """Get all alerts linked to an incident."""
    result = await db.execute(
        select(Alert).where(Alert.incident_id == incident_id).order_by(desc(Alert.detected_at))
    )
    alerts = result.scalars().all()
    return [AlertResponse.model_validate(a) for a in alerts]


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    data: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update incident fields and status."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    now = datetime.utcnow()

    if data.title is not None:
        incident.title = data.title
    if data.description is not None:
        incident.description = data.description
    if data.severity is not None:
        incident.severity = data.severity
    if data.status is not None:
        incident.status = data.status
        if data.status in ("resolution", "closed") and not incident.closed_at:
            incident.closed_at = now
    if data.assigned_analyst is not None:
        incident.assigned_analyst = data.assigned_analyst
    if data.affected_assets is not None:
        incident.affected_assets = data.affected_assets
    if data.attack_category is not None:
        incident.attack_category = data.attack_category
    if data.indicators is not None:
        incident.indicators = data.indicators
    if data.resolution is not None:
        incident.resolution = data.resolution
    if data.response_actions is not None:
        incident.response_actions = data.response_actions

    incident.updated_at = now

    # Create timeline note for status changes
    if data.status and data.status != old_status:
        note = IncidentNote(
            incident_id=incident.id,
            author=current_user.name,
            content=f"Status changed from '{old_status}' to '{data.status}' by {current_user.name}.",
            note_type="timeline",
        )
        db.add(note)
        await auto_notify_on_incident(db, incident, "status_changed")

    await db.commit()
    await db.refresh(incident)
    return IncidentResponse.model_validate(incident)


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse)
async def add_incident_note(
    incident_id: int,
    data: IncidentNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add an investigation/response note to an incident."""
    # Verify incident exists
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")

    note = IncidentNote(
        incident_id=incident_id,
        author=current_user.name,
        content=data.content,
        note_type=data.note_type,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return IncidentNoteResponse.model_validate(note)


@router.post("/{incident_id}/link-alerts")
async def link_alerts_to_incident(
    incident_id: int,
    alert_ids: list[int],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Link one or more alerts to an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    linked = 0
    existing_ids = incident.related_alert_ids or []

    for aid in alert_ids:
        a_result = await db.execute(select(Alert).where(Alert.id == aid))
        alert = a_result.scalar_one_or_none()
        if alert:
            alert.incident_id = incident_id
            if aid not in existing_ids:
                existing_ids.append(aid)
            linked += 1

    incident.related_alert_ids = existing_ids
    await db.commit()

    return {"message": f"Linked {linked} alerts to incident #{incident_id}"}


# ── SOAR Playbook Execution ────────────────────────────────────────────────

@router.post("/{incident_id}/soar", response_model=SoarActionResponse)
async def execute_soar_playbook(
    incident_id: int,
    data: SoarActionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Execute an automated/semi-automated SOAR remediation action."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    action_type = data.action_type.lower()
    target = data.target

    # Simulate realistic orchestration response summaries
    if action_type == "block_ip":
        summary = f"IP address {target} has been added to the border firewall blocklist and active connection states dropped."
    elif action_type == "isolate_host":
        summary = f"Host {target} moved to Quarantine VLAN. Port isolation rule applied across all edge switches."
    elif action_type == "revoke_session":
        summary = f"User session tokens for {target} revoked in auth cache. Account locked pending administrator unlock."
    elif action_type == "rate_limit":
        summary = f"Rate limiting policy enforced on {target}. Maximum 50 req/sec threshold applied."
    else:
        summary = f"Custom playbook '{action_type}' successfully executed against target {target}."

    action = SoarAction(
        action_type=action_type,
        target=target,
        incident_id=incident_id,
        executed_by=current_user.name,
        status="SUCCESS",
        result_summary=summary,
        parameters=data.parameters or {},
    )
    db.add(action)
    await db.flush()

    # Append action to incident response_actions JSON
    existing_actions = list(incident.response_actions or [])
    existing_actions.append({
        "action_id": action.id,
        "type": action_type,
        "target": target,
        "status": "SUCCESS",
        "timestamp": datetime.utcnow().isoformat(),
        "executed_by": current_user.name,
        "summary": summary,
    })
    incident.response_actions = existing_actions

    # Add timeline note
    note = IncidentNote(
        incident_id=incident_id,
        author="SOAR Engine",
        content=f"SOAR Action Executed: [{action_type.upper()}] on '{target}'. {summary}",
        note_type="response",
    )
    db.add(note)

    await db.commit()
    await db.refresh(action)
    return SoarActionResponse.model_validate(action)


@router.get("/{incident_id}/soar-actions")
async def get_incident_soar_actions(incident_id: int, db: AsyncSession = Depends(get_db)):
    """Get all SOAR actions executed for a specific incident."""
    result = await db.execute(
        select(SoarAction)
        .where(SoarAction.incident_id == incident_id)
        .order_by(desc(SoarAction.created_at))
    )
    actions = result.scalars().all()
    return [SoarActionResponse.model_validate(a) for a in actions]


@router.get("/soar-actions/recent")
async def get_recent_soar_actions(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Get global recent SOAR playbook executions for audit logs."""
    result = await db.execute(
        select(SoarAction).order_by(desc(SoarAction.created_at)).limit(limit)
    )
    actions = result.scalars().all()
    return [SoarActionResponse.model_validate(a) for a in actions]

