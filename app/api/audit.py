import hashlib
import hmac
from app.auth.security import get_jwt_secret

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditEvent, User


def record_audit(
    db: Session,
    user: User | None,
    action: str,
    outcome: str = "success",
    indicator: str | None = None,
    indicator_type: str | None = None,
    request: Request | None = None,
) -> None:
    digest = (
        hmac.new(get_jwt_secret().encode(), indicator.encode("utf-8"), hashlib.sha256).hexdigest()
        if indicator is not None
        else None
    )

    source_ip = request.client.host if request and request.client else None

    event = AuditEvent(
        user_id=user.id if user else None,
        action=action,
        indicator_type=indicator_type,
        indicator_digest=digest,
        outcome=outcome,
        source_ip=source_ip,
    )

    db.add(event)
    db.commit()
