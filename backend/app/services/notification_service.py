"""
Notification Service — Generates in-app notifications for security events.
Called from alert/incident workflows to auto-notify analysts.
"""
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.user import Notification, User


async def create_notification(
    db: AsyncSession,
    title: str,
    message: str,
    severity: str = "INFO",
    notif_type: str = "alert",
    related_id: int = None,
    related_type: str = None,
    user_id: int = None,
):
    """Create a notification record. If user_id is None, it's a broadcast."""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        severity=severity,
        notif_type=notif_type,
        related_id=related_id,
        related_type=related_type,
    )
    db.add(notification)
    return notification


async def auto_notify_on_alert(db: AsyncSession, alert):
    """Auto-generate notifications for critical/high severity alerts."""
    if alert.severity in ("CRITICAL", "HIGH"):
        await create_notification(
            db,
            title=f"{alert.severity} Alert: {alert.attack_type}",
            message=f"Threat detected from {alert.source_ip} → {alert.dest_ip}:{alert.port}. "
                    f"Risk score: {alert.risk_score}/100. Confidence: {alert.confidence:.1%}.",
            severity=alert.severity,
            notif_type="alert",
            related_id=alert.id,
            related_type="alert",
        )


async def auto_notify_on_incident(db: AsyncSession, incident, event_type: str = "created"):
    """Generate notifications for incident lifecycle events."""
    event_messages = {
        "created": f"New incident created: {incident.title}",
        "escalated": f"Incident escalated to {incident.severity}: {incident.title}",
        "assigned": f"Incident assigned to {incident.assigned_analyst}: {incident.title}",
        "resolved": f"Incident resolved: {incident.title}",
        "closed": f"Incident closed: {incident.title}",
        "status_changed": f"Incident status changed to {incident.status}: {incident.title}",
    }
    message = event_messages.get(event_type, f"Incident updated: {incident.title}")

    await create_notification(
        db,
        title=f"Incident #{incident.id}: {event_type.replace('_', ' ').title()}",
        message=message,
        severity=incident.severity,
        notif_type="incident",
        related_id=incident.id,
        related_type="incident",
    )
