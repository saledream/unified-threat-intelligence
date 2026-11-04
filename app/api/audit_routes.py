from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import require_admin
from app.database import get_db
from app.models import AuditEvent, User

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get("/events")
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    action: str | None = Query(default=None, min_length=1, max_length=100),
    outcome: str | None = Query(default=None, min_length=1, max_length=40),
    user_id: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    filters = []
    if action:
        filters.append(AuditEvent.action == action)
    if outcome:
        filters.append(AuditEvent.outcome == outcome)
    if user_id is not None:
        filters.append(AuditEvent.user_id == user_id)

    total = db.scalar(
        select(func.count(AuditEvent.id)).where(*filters)
    ) or 0

    rows = db.execute(
        select(AuditEvent, User.username)
        .outerjoin(User, AuditEvent.user_id == User.id)
        .where(*filters)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()

    events = [
        {
            "id": event.id,
            "user_id": event.user_id,
            "username": username,
            "action": event.action,
            "indicator_type": event.indicator_type,
            "indicator_digest": event.indicator_digest,
            "outcome": event.outcome,
            "source_ip": event.source_ip,
            "created_at": event.created_at,
        }
        for event, username in rows
    ]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events,
    }
