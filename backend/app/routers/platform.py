"""Platform administration routes: teams, audit history and safe webhook setup."""
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.user import AuditEvent, User, WebhookConfig

router = APIRouter(prefix="/api", tags=["Platform"])

async def audit(db: AsyncSession, user: User | None, action: str, resource_type: str, resource_id: str | None = None, details: dict | None = None):
    db.add(AuditEvent(user_id=user.id if user else None, actor=user.email if user else "system", action=action, resource_type=resource_type, resource_id=resource_id, details=details or {}))

@router.get("/users")
async def list_users(_: User = Depends(require_role(["admin", "soc_manager"])), db: AsyncSession = Depends(get_db)):
    users = (await db.execute(select(User).order_by(User.created_at.desc()))).scalars().all()
    return [{"id": u.id, "name": u.name, "email": u.email, "phone": u.phone, "role": u.role, "created_at": u.created_at} for u in users]

@router.get("/audit")
async def list_audit(_: User = Depends(require_role(["admin", "soc_manager"])), db: AsyncSession = Depends(get_db)):
    events = (await db.execute(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100))).scalars().all()
    return [{"id": e.id, "actor": e.actor, "action": e.action, "resource_type": e.resource_type, "resource_id": e.resource_id, "details": e.details, "created_at": e.created_at} for e in events]

class WebhookInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    endpoint_url: str = Field(min_length=10, max_length=500)
    event_types: list[str] = ["incident.created"]
    is_enabled: bool = False

def validate_endpoint(endpoint_url: str):
    parsed = urlparse(endpoint_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Webhook endpoint must use HTTPS")
    allowlist = [host.strip() for host in settings.WEBHOOK_ALLOWLIST.split(",") if host.strip()]
    if allowlist and parsed.hostname not in allowlist:
        raise HTTPException(status_code=400, detail="Webhook host is not in the configured allow-list")

@router.get("/webhooks")
async def list_webhooks(_: User = Depends(require_role(["admin"])), db: AsyncSession = Depends(get_db)):
    hooks = (await db.execute(select(WebhookConfig).order_by(WebhookConfig.created_at.desc()))).scalars().all()
    return [{"id": h.id, "name": h.name, "endpoint_url": h.endpoint_url, "event_types": h.event_types, "is_enabled": h.is_enabled, "created_at": h.created_at} for h in hooks]

@router.post("/webhooks", status_code=status.HTTP_201_CREATED)
async def create_webhook(data: WebhookInput, user: User = Depends(require_role(["admin"])), db: AsyncSession = Depends(get_db)):
    validate_endpoint(data.endpoint_url)
    hook = WebhookConfig(**data.model_dump(), created_by=user.id)
    db.add(hook)
    await audit(db, user, "webhook.created", "webhook", details={"name": data.name, "enabled": data.is_enabled})
    await db.commit()
    await db.refresh(hook)
    return {"id": hook.id, "name": hook.name, "is_enabled": hook.is_enabled}
